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
}

// PublicMatch là payload an toàn để trả ra ngoài (CLI/JSON/CSV/audit).
type PublicMatch struct {
	RuleID     string  `json:"rule_id"`
	Offset     int64   `json:"offset"`
	Length     int     `json:"length"`
	Confidence float64 `json:"confidence"`
}

func (m ScanMatch) ToPublic() PublicMatch {
	return PublicMatch{
		RuleID:     m.RuleID,
		Offset:     m.ByteOffset,
		Length:     m.Length,
		Confidence: m.Confidence,
	}
}
