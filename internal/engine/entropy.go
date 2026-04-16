// Package engine — Shannon entropy analysis để phát hiện dữ liệu mã hóa/key bí mật.
package engine

import "math"

// ShannonEntropy tính entropy Shannon của chuỗi byte.
// Kết quả: 0.0 (hoàn toàn đồng nhất) đến 8.0 (hoàn toàn ngẫu nhiên).
// Entropy > 4.5 bits/byte → nghi ngờ dữ liệu mã hóa hoặc secret key.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := [256]float64{}
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// IsHighEntropy kiểm tra xem đoạn dữ liệu có entropy cao không (ngưỡng mặc định 4.5).
func IsHighEntropy(data []byte, threshold float64) bool {
	return ShannonEntropy(data) >= threshold
}
