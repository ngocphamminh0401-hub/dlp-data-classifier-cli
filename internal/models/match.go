package models

// ScanMatch là dữ liệu nội bộ cho một lần match; không được serialize trực tiếp -> tránh lộ dữ liệu nhạy cảm.
type ScanMatch struct {
	RuleID     string
	RuleName   string
	Category   string
	ByteOffset int64
	Length     int
	Value      string
	Context    string
	Confidence float64

	// Level là cấp độ HIỆU LỰC của match sau escalation / negation / level_gate
	// (0..3, khớp engine.ClassificationLevel). Dùng để xác định "decisive match"
	// (Level == FinalLevel) trong FileConfidence nhánh A.
	Level int
	// Validated = match đã qua validator thuật toán (Luhn, CCCD prefix, bank prefix).
	Validated bool
}

// PublicMatch là payload an toàn để trả ra ngoài (CLI/JSON/CSV/audit).
type PublicMatch struct {
	RuleID     string  `json:"rule_id"`
	Offset     int64   `json:"offset"`
	Length     int     `json:"length"`
	Confidence float64 `json:"confidence"`
	Level      int     `json:"level"`
	Validated  bool    `json:"validated"`
}

func (m ScanMatch) ToPublic() PublicMatch {
	return PublicMatch{
		RuleID:     m.RuleID,
		Offset:     m.ByteOffset,
		Length:     m.Length,
		Confidence: m.Confidence,
		Level:      m.Level,
		Validated:  m.Validated,
	}
}
