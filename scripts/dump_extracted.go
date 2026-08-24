//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/vnpt/dlp-classifier/internal/extractor"
)

func main() {
	b, err := extractor.Extract(os.Args[1])
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	fmt.Println(string(b))
}
