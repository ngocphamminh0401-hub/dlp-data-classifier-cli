// unix_socket.go — Unix Domain Socket transport cho DLP agent.
//
// # Wire format
//
// Mỗi message (Request hoặc Response) được đóng khung theo cấu trúc:
//
//	┌──────────────────────────┬───────────────────────────────────────┐
//	│  4 bytes (uint32 BE)     │         JSON payload                  │
//	│  độ dài payload (bytes)  │  Request{} hoặc Response{}            │
//	└──────────────────────────┴───────────────────────────────────────┘
//
// Không dùng delimiter (\n) để tránh escaping phức tạp với JSON chứa newline.
// Length prefix đơn giản hơn và hiệu quả hơn cho binary framing.
//
// # Concurrency model
//
// Mỗi kết nối được xử lý trong goroutine riêng (handleUnixConn).
// Trong một kết nối, các request được xử lý tuần tự (sequential pipelining):
// client gửi request → chờ toàn bộ response → gửi request tiếp theo.
//
// Nếu cần concurrency cao hơn, client nên mở nhiều kết nối Unix socket.
//
// # Idle timeout
//
// Server đặt read deadline 30s giữa các request để phát hiện client bị treo.
// Deadline bị reset về 0 trong khi đang xử lý (scan có thể mất vài giây).
package agent

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// idleReadTimeout là thời gian tối đa server chờ request tiếp theo từ client.
// Sau khoảng thời gian này không có dữ liệu, kết nối bị đóng.
const idleReadTimeout = 30 * time.Second

// ─── Server side ─────────────────────────────────────────────────────────────

// serveUnix tạo Unix domain socket và chấp nhận kết nối.
// Block cho đến khi context bị huỷ hoặc có lỗi không phục hồi được.
func (s *Server) serveUnix() error {
	// Xoá socket cũ nếu còn lại từ lần chạy trước (ví dụ: crash).
	_ = os.Remove(s.cfg.SocketPath)

	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.SocketPath, err)
	}
	defer ln.Close()

	// Đóng listener khi context bị huỷ để Accept() unblock.
	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil // shutdown sạch
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.activeConn.Add(1)
		go func() {
			defer s.activeConn.Add(-1)
			s.handleUnixConn(conn)
		}()
	}
}

// handleUnixConn xử lý vòng lặp request–response trên một kết nối Unix socket.
// Kết nối bị đóng khi: client disconnect, framing error, hoặc idle timeout.
func (s *Server) handleUnixConn(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	slog.Debug("agent: kết nối mới", "remote", remote)
	defer slog.Debug("agent: kết nối đóng", "remote", remote)

	for {
		// Đặt deadline đọc để phát hiện client bị treo/mất kết nối.
		_ = conn.SetReadDeadline(time.Now().Add(idleReadTimeout))

		req, err := readMessage[Request](conn)
		if err != nil {
			if err == io.EOF {
				return // client disconnect bình thường
			}
			if isNetTimeout(err) {
				slog.Debug("agent: idle timeout", "remote", remote)
				return
			}
			slog.Debug("agent: lỗi đọc request", "remote", remote, "err", err)
			return
		}

		// Reset deadline trong khi xử lý (scan có thể mất vài giây).
		_ = conn.SetReadDeadline(time.Time{})

		slog.Debug("agent: request nhận được",
			"id", req.ID,
			"action", req.Action,
			"path", req.Path,
		)

		// mu bảo vệ ghi đồng thời nếu dispatch spawn goroutine (vd: shutdown async).
		var mu sync.Mutex
		s.dispatch(req, func(resp *Response) error {
			mu.Lock()
			defer mu.Unlock()
			return writeMessage(conn, resp)
		})
	}
}

// ─── Framing ──────────────────────────────────────────────────────────────────

// readMessage đọc một message có length prefix từ r và unmarshal vào kiểu T.
//
// Cấu trúc đọc:
//  1. Đọc 4 byte → uint32 big-endian = độ dài payload
//  2. Kiểm tra độ dài ≤ MaxMessageBytes
//  3. Đọc đúng payload bytes
//  4. json.Unmarshal payload → *T
func readMessage[T any](r io.Reader) (*T, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err // io.EOF khi client đóng kết nối
	}

	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen == 0 {
		return nil, fmt.Errorf("framing: message rỗng (length=0)")
	}
	if uint64(msgLen) > uint64(MaxMessageBytes) {
		return nil, fmt.Errorf("framing: message quá lớn (%d bytes, tối đa %d)", msgLen, MaxMessageBytes)
	}

	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("framing: đọc payload: %w", err)
	}

	var v T
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, fmt.Errorf("framing: unmarshal JSON: %w", err)
	}
	return &v, nil
}

// writeMessage marshal v thành JSON và ghi với 4-byte length prefix vào w.
//
// Ghi là atomic cho một message (length + payload trong một Write nếu ≤ buffer),
// nhưng caller chịu trách nhiệm đảm bảo không có concurrent writes trên cùng w.
func writeMessage(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("framing: marshal JSON: %w", err)
	}
	if len(payload) > MaxMessageBytes {
		return fmt.Errorf("framing: response quá lớn (%d bytes)", len(payload))
	}

	// Ghi length prefix + payload trong một lần để tránh write split.
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)

	_, err = w.Write(buf)
	return err
}

// isNetTimeout kiểm tra xem err có phải lỗi timeout network không.
func isNetTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// ─── Client helper (để test và tích hợp) ─────────────────────────────────────

// Dial kết nối đến Unix socket của agent và trả về *Conn để gửi Request.
// Caller phải gọi conn.Close() sau khi dùng xong.
//
// Ví dụ sử dụng:
//
//	conn, err := agent.Dial("/tmp/dlp.sock")
//	resp, err := conn.Send(&agent.Request{
//	    ID:     "req-001",
//	    Action: agent.ActionScanFile,
//	    Path:   "/data/report.docx",
//	})
func Dial(socketPath string) (*Conn, error) {
	nc, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	return &Conn{nc: nc}, nil
}

// Conn là kết nối client đến agent qua Unix socket.
type Conn struct {
	nc net.Conn
	mu sync.Mutex
}

// Send gửi một Request và đọc tất cả Response cho đến khi stream kết thúc.
//
// Với scan_file / ping / status / shutdown: trả về slice gồm 1 Response.
// Với scan_directory: trả về N Response (streaming) + 1 Response (stream_end).
//
// Lỗi network hoặc framing được wrap và trả về trong error.
func (c *Conn) Send(req *Request) ([]*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeMessage(c.nc, req); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	var responses []*Response
	for {
		resp, err := readMessage[Response](c.nc)
		if err != nil {
			return responses, fmt.Errorf("recv: %w", err)
		}
		responses = append(responses, resp)

		// Dừng đọc khi nhận response cuối cùng của stream.
		if resp.Status != StatusStreaming {
			break
		}
	}
	return responses, nil
}

// Close đóng kết nối đến agent.
func (c *Conn) Close() error {
	return c.nc.Close()
}
