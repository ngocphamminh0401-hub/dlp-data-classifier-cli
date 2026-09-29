// telemetry.go — FileScanTelemetry: đếm các sự kiện "near-miss" trong pipeline.
//
// # Mục tiêu (Pha 1 — Instrumentation)
//
// Đếm lại toàn bộ sự kiện hiện đang bị continue/vứt bỏ trong Engine.Scan mà
// KHÔNG đổi kết quả classification (Level / FinalLevel). Dữ liệu này chưa dùng
// để routing — chỉ để dump ở Pha 2 phục vụ fit lớp prior/hiệu chỉnh.
//
// # Bất biến
//
// Mỗi counter chỉ là một dòng `tel.X++` ngay tại nhánh continue/reject ĐÃ CÓ
// SẴN — không refactor logic xung quanh. Xem test hồi quy
// TestTelemetryClassificationUnchanged: Level/FinalLevel đầu ra không đổi.
package engine

import "regexp"

// FileScanTelemetry gom số liệu near-miss cho MỘT chunk (Engine.Scan). Scanner
// gộp qua các chunk của cùng file bằng Merge để có số liệu cấp file.
type FileScanTelemetry struct {
	// ── 6 counter tại các nhánh continue/reject sẵn có ────────────────────
	ContextRequiredSkipCount int `json:"context_required_skip_count"` // pattern context_required nhưng thiếu keyword hit
	ValidatorFailCount       int `json:"validator_fail_count"`        // Luhn / CCCD / bank prefix... enforced && !passed
	ProximityRejectCount     int `json:"proximity_reject_count"`      // exclude_if_no_keywords / proximity_window reject
	NegationSuppressCount    int `json:"negation_suppress_count"`     // negation_filter action=suppress
	NegationDowngradeCount   int `json:"negation_downgrade_count"`    // negation_filter action=downgrade_to_gate
	LevelGateDowngradeCount  int `json:"level_gate_downgrade_count"`  // applyLevelGate hạ về fallback_level

	// KeywordHitNoMatchRules: ruleID có keyword hit trong chunk nhưng KHÔNG
	// tạo ra match nào (giá trị = số keyword hit của rule đó).
	KeywordHitNoMatchRules map[string]int `json:"keyword_hit_no_match_rules,omitempty"`

	// KeywordHitNoMatchPrimaryRuleCount: số RULE có ≥1 PRIMARY keyword hit nhưng
	// 0 match — near-miss "đã engaged" (file thật sự nhắc từ khóa chính của rule
	// mà rule vẫn không match). Chặt hơn KeywordHitNoMatchRules (đếm cả secondary
	// / total hits → có "sàn" cao trên mọi file, đo verbosity). Dùng làm β1
	// Nhánh B thay cho keyword_hit_no_match_total.
	KeywordHitNoMatchPrimaryRuleCount int `json:"keyword_hit_no_match_primary_rules"`

	// ── 3 feature bổ sung (không có điểm continue sẵn — tính mới) ──────────
	ChunkCount              int   `json:"chunk_count"`                // số chunk đã scan thành công
	ChunkErrorCount         int   `json:"chunk_error_count"`          // số chunk lỗi (timeout...) — xem chunk_error_ratio
	TotalBytes              int64 `json:"total_bytes"`                // tổng byte nội dung đã scan — xem file_effective_length
	UnstructuredNumericHits int   `json:"unstructured_numeric_hits"`  // dãy 8–19 chữ số KHÔNG nằm trong match nào
	DocContextDiscountCount int   `json:"doc_context_discount_count"` // số chunk có từ khóa "ví dụ/template/SOP"

	// ── Pha 8: tín hiệu near-miss under-classification (Nhánh A) ──────────
	// Đo mức độ "suýt leo thang" — graded, KHÔNG nhị phân. Chỉ quan sát tại
	// nhánh đã reject/không-escalate; không đổi Level/FinalLevel.
	EscalationNearMissScore      float64 `json:"escalation_near_miss_score"`       // S1: escalation keyword trong penumbra 300–900B quanh match
	CompoundNearMissScore        float64 `json:"compound_near_miss_score"`         // S2: compound rule (sẽ nâng cấp) đủ N−1/N điều kiện
	ValidatorFailInContextCount  int     `json:"validator_fail_in_context_count"`  // S3: format-match fail validator NHƯNG có từ vựng PII gần đó
	HrSensitiveLexiconNoRuleCount int    `json:"hr_sensitive_lexicon_no_rule_count"` // HR blind-spot: từ vựng HR nhạy cảm có mặt, 0 rule HR engaged
}

// docContextProbeKeywords: từ khóa "tài liệu hướng dẫn / ví dụ / template" —
// tái dùng ý nghĩa của placeholder_exclusion.doc_context_discount nhưng ở mức
// PROBE cấp chunk (chỉ log, không ảnh hưởng confidence). Cố ý giữ hẹp quanh
// "ví dụ / template / SOP" như đặc tả Pha 1.
var docContextProbeKeywords = []string{
	"ví dụ", "vi du", "template", "sop", "biểu mẫu", "bieu mau",
	"minh họa", "minh hoa", "mẫu điền", "mau dien",
}

// sensitiveContextKeywords (S3): từ vựng cho thấy "chỗ này ĐÁNG LẼ có PII cấu
// trúc thật" — đối ngẫu của docContextProbeKeywords. Dùng để lọc validator-fail:
// chỉ đếm khi checksum sai NHƯNG ngữ cảnh xác nhận đây không phải số random.
var sensitiveContextKeywords = []string{
	"số tài khoản", "so tai khoan", "tài khoản ngân hàng", "tai khoan ngan hang",
	"thẻ tín dụng", "the tin dung", "hồ sơ bệnh án", "ho so benh an",
	"kết quả xét nghiệm", "ket qua xet nghiem", "hợp đồng lao động", "hop dong lao dong",
	"bảo hiểm xã hội", "bao hiem xa hoi", "mã số thuế", "ma so thue",
	"số căn cước", "so can cuoc", "chứng minh nhân dân", "chung minh nhan dan",
}

// hrSensitiveLexicon (HR probe): từ vựng hồ sơ HR nhạy cảm (kỷ luật / điều tra /
// dữ liệu đặc biệt GDPR Art.9 trong ngữ cảnh nhân sự). Blind spot: rule HR
// thiếu coverage → nhiều file HR RESTRICTED không match rule nào.
var hrSensitiveLexicon = []string{
	"kỷ luật", "ky luat", "quấy rối", "quay roi", "sa thải", "sa thai",
	"khiếu nại", "khieu nai", "điều tra nội bộ", "dieu tra noi bo",
	"dân tộc", "dan toc", "tôn giáo", "ton giao", "kết nạp đảng", "ket nap dang",
	"tiền án", "tien an", "tranh chấp lao động", "tranh chap lao dong",
	"lương thưởng", "luong thuong", "đánh giá hiệu suất", "danh gia hieu suat",
}

// containsSensitiveContextNear: có từ vựng PII cấu trúc trong ±window byte
// quanh [start,end) của chunk không.
func containsSensitiveContextNear(chunk []byte, start, end, window int) bool {
	s := start - window
	if s < 0 {
		s = 0
	}
	e := end + window
	if e > len(chunk) {
		e = len(chunk)
	}
	return containsAnyKeyword(chunk[s:e], sensitiveContextKeywords)
}

// unstructuredNumericRe khớp dãy 8–19 chữ số liên tiếp. Kết quả còn được lọc
// thêm (bỏ fragment của dãy dài hơn) và đối chiếu với danh sách match trong
// countUnstructuredNumericHits.
var unstructuredNumericRe = regexp.MustCompile(`\d{8,19}`)

// addKeywordHitNoMatch cộng n vào KeywordHitNoMatchRules[ruleID] (khởi tạo map
// nếu cần).
func (t *FileScanTelemetry) addKeywordHitNoMatch(ruleID string, n int) {
	if n == 0 {
		return
	}
	if t.KeywordHitNoMatchRules == nil {
		t.KeywordHitNoMatchRules = make(map[string]int)
	}
	t.KeywordHitNoMatchRules[ruleID] += n
}

// Merge cộng dồn số liệu của một chunk (o) vào bộ tích lũy cấp file (t).
func (t *FileScanTelemetry) Merge(o FileScanTelemetry) {
	t.ContextRequiredSkipCount += o.ContextRequiredSkipCount
	t.ValidatorFailCount += o.ValidatorFailCount
	t.ProximityRejectCount += o.ProximityRejectCount
	t.NegationSuppressCount += o.NegationSuppressCount
	t.NegationDowngradeCount += o.NegationDowngradeCount
	t.LevelGateDowngradeCount += o.LevelGateDowngradeCount
	t.ChunkCount += o.ChunkCount
	t.ChunkErrorCount += o.ChunkErrorCount
	t.TotalBytes += o.TotalBytes
	t.UnstructuredNumericHits += o.UnstructuredNumericHits
	t.DocContextDiscountCount += o.DocContextDiscountCount
	t.KeywordHitNoMatchPrimaryRuleCount += o.KeywordHitNoMatchPrimaryRuleCount
	t.EscalationNearMissScore += o.EscalationNearMissScore
	t.CompoundNearMissScore += o.CompoundNearMissScore
	t.ValidatorFailInContextCount += o.ValidatorFailInContextCount
	t.HrSensitiveLexiconNoRuleCount += o.HrSensitiveLexiconNoRuleCount
	for k, v := range o.KeywordHitNoMatchRules {
		t.addKeywordHitNoMatch(k, v)
	}
}

// ChunkErrorRatio trả về tỉ lệ chunk lỗi / tổng chunk (0 nếu chưa scan chunk
// nào). Xem tailieu/chot-pham-vi-ky-thuat-prior-pha2.md mục 4.1: hiện extractor
// là all-or-nothing theo file nên tỉ lệ này gần như chỉ nhận giá trị 0 hoặc 1.
func (t FileScanTelemetry) ChunkErrorRatio() float64 {
	total := t.ChunkCount + t.ChunkErrorCount
	if total == 0 {
		return 0
	}
	return float64(t.ChunkErrorCount) / float64(total)
}

// countUnstructuredNumericHits đếm số dãy 8–19 chữ số trong chunk KHÔNG nằm
// trong bất kỳ match nào (matches có Offset tuyệt đối = baseOffset + vị trí
// trong chunk). Dãy là fragment của một chuỗi số dài hơn (ký tự sát 2 đầu vẫn
// là chữ số) bị bỏ qua để không đếm nhầm một số dài thành nhiều hit.
func countUnstructuredNumericHits(chunk []byte, matches []RuleMatch, baseOffset int64) int {
	locs := unstructuredNumericRe.FindAllIndex(chunk, -1)
	if len(locs) == 0 {
		return 0
	}
	count := 0
	for _, loc := range locs {
		s, e := loc[0], loc[1]
		if s > 0 && chunk[s-1] >= '0' && chunk[s-1] <= '9' {
			continue
		}
		if e < len(chunk) && chunk[e] >= '0' && chunk[e] <= '9' {
			continue
		}
		absStart := baseOffset + int64(s)
		absEnd := baseOffset + int64(e)
		inMatch := false
		for _, m := range matches {
			if absStart < m.Offset+int64(m.Length) && absEnd > m.Offset {
				inMatch = true
				break
			}
		}
		if !inMatch {
			count++
		}
	}
	return count
}
