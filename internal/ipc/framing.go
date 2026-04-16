package ipc

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

const maxFrameBytes = 32 * 1024 * 1024

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty frame")
	}
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrameBytes {
		return nil, fmt.Errorf("invalid frame length: %d", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
