package ipc

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"
)

type Client struct {
	conn net.Conn
	rd   *bufio.Reader
	mu   sync.Mutex
}

func Dial(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial unix socket: %w", err)
	}
	return &Client{conn: conn, rd: bufio.NewReader(conn)}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Scan(req Request) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	payload, err := MarshalEnvelope(Envelope{Type: TypeScan, Request: &req})
	if err != nil {
		return nil, err
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(heartbeatTimeout))
	if err := writeFrame(c.conn, payload); err != nil {
		return nil, err
	}
	_ = c.conn.SetWriteDeadline(time.Time{})

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		raw, err := readFrame(c.rd)
		if err != nil {
			return nil, err
		}
		_ = c.conn.SetReadDeadline(time.Time{})

		env, err := UnmarshalEnvelope(raw)
		if err != nil {
			return nil, err
		}

		switch env.Type {
		case TypePing:
			pong, err := MarshalEnvelope(Envelope{Type: TypePong})
			if err != nil {
				return nil, err
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(heartbeatTimeout))
			if err := writeFrame(c.conn, pong); err != nil {
				return nil, err
			}
			_ = c.conn.SetWriteDeadline(time.Time{})
		case TypeResult:
			if env.Response == nil {
				return nil, fmt.Errorf("missing response payload")
			}
			return env.Response, nil
		}
	}
}
