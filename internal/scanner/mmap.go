package scanner

import (
	"os"
	"time"

	mmap "github.com/edsrzf/mmap-go"
)

func (s *Scanner) scanMMAP(f *os.File, result *ScanResult, deadline time.Time) error {
	mapped, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		return err
	}
	defer mapped.Unmap()

	decoded, err := decodeContent(mapped)
	if err != nil {
		return err
	}

	return s.scanBuffer(decoded, result, deadline)
}
