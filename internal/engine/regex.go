// regex.go — Pattern matching, confidence scoring, và validator functions.
//
// # Luồng xử lý cho một rule (matchAllPatterns)
//
//  1. Với mỗi RulePattern trong rule:
//     a. Nếu context_required = true VÀ không có keyword nào → bỏ qua pattern
//     b. Chạy compiled regex → danh sách [start, end] offsets
//
//  2. Với mỗi regex match:
//     a. Tính base score: pattern.Confidence × rule.Weight
//     b. Distance-weighted context boost — 3 vùng khoảng cách:
//        ┌──────────────────────────────────────────────────────────────────┐
//        │  Zone 1: khoảng cách 0–20 byte  → primary +0.15 / secondary +0.07│
//        │  Zone 2: khoảng cách 21–50 byte → primary +0.10 / secondary +0.05│
//        │  Zone 3: khoảng cách 51–window  → primary +0.05 / secondary +0.02│
//        │  Ngoài window: không boost (keyword không liên quan)             │
//        │  Tổng boost tối đa: +0.30 (capped)                              │
//        └──────────────────────────────────────────────────────────────────┘
//        Tại sao distance-weighted?
//        "visa" ngay trước "4532015112830366" xác nhận mạnh hơn "visa" cách 180 byte.
//        Từ xa → ngữ cảnh yếu hơn → boost thấp hơn.
//     c. Validators (Luhn, ...):
//        - Pass → confidence = max(confidence, 0.99)  [validator confirms match]
//        - Fail → bỏ qua match hoàn toàn             [hard reject FP]
//     d. FP reduction: ExcludeIfNoKeywords + CVV/expiry boost
//     e. Nếu confidence < minConfidence → bỏ qua
//     f. Xác định cấp độ (override_level hoặc rule.ParsedLevel)
//     g. Kiểm tra escalation keywords → nâng cấp nếu cần
//     h. Thêm vào kết quả
//
// # Confidence formula
//
//	score = pattern.Confidence × rule.Weight
//	score += distanceWeightedBoost(kwHits, matchStart, matchEnd, window)  // tối đa +0.30
//	if validator_pass: score = max(score, 0.99)
//	if no_keywords AND context_required: skip
//	if cvv_expiry_near: score += FPReduction.CVVExpiryBoost
//	score = clamp(score, 0.0, 1.0)
package engine

import (
	"bytes"
	"regexp"
	"strings"
)

// matchOpts chứa các tham số scoring được truyền từ Engine.Scan().
type matchOpts struct {
	minConfidence float64 // Ngưỡng tối thiểu; match dưới ngưỡng bị loại bỏ
	contextWindow int     // Phạm vi byte quanh match để tìm keyword boost
}

// ─── CVV / Expiry patterns (compile once) ────────────────────────────────────

// cvvPattern khớp CVV 3–4 số (có context "cvv", "cvc", "security code").
// Không dùng để match blindly — chỉ dùng trong cửa sổ ngữ cảnh của credit card.
var (
	cvvPattern    = regexp.MustCompile(`(?i)(?:cvv|cvc|security\s*code)\D{0,5}(\d{3,4})\b`)
	expiryPattern = regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[/\-](?:\d{2}|\d{4})\b`)
)

// ─── matchAllPatterns ────────────────────────────────────────────────────────

// matchAllPatterns chạy toàn bộ pattern của rule trên chunk, áp dụng confidence
// scoring, và trả về các RuleMatch vượt ngưỡng minConfidence.
//
// baseOffset là vị trí byte của chunk trong file gốc — được cộng vào Offset
// của mỗi match để kết quả phản ánh vị trí tuyệt đối trong file.
//
// Hàm này là hot path; gọi hàng triệu lần → không allocate nếu không có match.
func matchAllPatterns(chunk []byte, rule *Rule, hits HitMap, baseOffset int64, opts matchOpts) []RuleMatch {
	var out []RuleMatch

	for patIdx := range rule.Patterns {
		pat := &rule.Patterns[patIdx]
		if pat.Compiled == nil {
			continue
		}

		// ── Bộ lọc context_required ──────────────────────────────────────
		// Nếu pattern yêu cầu ngữ cảnh từ khóa (ví dụ: CMND 9 số) mà không
		// tìm thấy keyword nào cho rule này → bỏ qua toàn bộ pattern.
		// Tiết kiệm CPU: không chạy regex khi rõ ràng sẽ là false positive.
		if pat.ContextRequired && !hits.HasRule(rule.ID) {
			continue
		}

		// ── Chạy regex ───────────────────────────────────────────────────
		locs := pat.Compiled.FindAllIndex(chunk, -1)
		if len(locs) == 0 {
			continue
		}

		for _, loc := range locs {
			start := int64(loc[0])
			end := int64(loc[1])
			matchBytes := chunk[loc[0]:loc[1]]

			// RE2 không hỗ trợ lookaround. Dùng post-filter để loại các case
			// placeholder/comment/noreply ngay sau khi match regex.
			if shouldSkipPostFilter(chunk, loc[0], loc[1], rule.ID, matchBytes) {
				continue
			}

			// ── 1. Base score ─────────────────────────────────────────────
			score := pat.Confidence * rule.Weight

			// ── 2. Distance-weighted context boost ────────────────────────
			// Keyword gần match → boost mạnh; keyword xa → boost yếu.
			// Zone 1 (0-20 byte): xác nhận mạnh (keyword ngay trước/sau số thẻ)
			// Zone 2 (21-50 byte): xác nhận vừa (keyword trong câu)
			// Zone 3 (51-window): xác nhận yếu (keyword cùng đoạn)
			score = clamp01(score + distanceWeightedBoost(hits, rule.ID, start, end, opts.contextWindow))

			// ── 3. Validators (Luhn, ...) ─────────────────────────────────
			// Validator = hard check: pass → rất chắc chắn; fail → loại bỏ hoàn toàn.
			if len(pat.Validators) > 0 {
				passed, enforced := applyValidators(matchBytes, pat.Validators)
				if enforced && !passed {
					continue // false positive đã bị lọc bởi thuật toán (vd: số thẻ sai Luhn)
				}
				if enforced && passed {
					score = clamp01(maxF(score, 0.99)) // validator xác nhận → confidence rất cao
				}
			}

			// ── 4. FP reduction: exclude_if_no_keywords ───────────────────
			// Cho các loại dữ liệu như số CMND/CCCD, số tài khoản — cần có keyword
			// đi kèm để phân biệt với số serial, mã sản phẩm, ...
			if rule.FPReduction.ExcludeIfNoKeywords && !hits.HasRule(rule.ID) {
				continue
			}

			// ── 5. CVV + Expiry context boost (cho credit card) ───────────
			if rule.FPReduction.CVVExpiryBoost > 0 {
				ctxStart := maxI(0, loc[0]-300)
				ctxEnd := minI(len(chunk), loc[1]+300)
				window := chunk[ctxStart:ctxEnd]
				if cvvPattern.Match(window) && expiryPattern.Match(window) {
					score = clamp01(score + rule.FPReduction.CVVExpiryBoost)
				}
			}

			// ── 6. Ngưỡng confidence ─────────────────────────────────────
			if score < opts.minConfidence {
				continue
			}

			// ── 7. Cấp độ phân loại ───────────────────────────────────────
			// Mặc định dùng cấp độ của rule; pattern có thể override (vd: email
			// @vnpt.vn trong rule email nâng từ INTERNAL → CONFIDENTIAL).
			level := rule.ParsedLevel
			if pat.OverrideLevel != "" {
				level = ParseLevel(pat.OverrideLevel)
			}
			level = adjustLevelPostFilter(rule.ID, matchBytes, level)

			// ── 8. Escalation keywords ────────────────────────────────────
			// Nếu phát hiện từ khóa escalation gần match → nâng cấp độ.
			// Ví dụ: "hợp đồng" + "quốc phòng" → PUBLIC → SECRET
			if rule.Escalation.EscalateTo != "" && len(rule.Escalation.Keywords) > 0 {
				level = checkEscalation(chunk, loc[0], loc[1], rule, level)
			}

			// ── 9. Preview (masked) ───────────────────────────────────────
			preview := maskPreview(matchBytes)

			// ── 10. Context snippet ───────────────────────────────────────
			ctxSnip := extractContext(chunk, loc[0], loc[1], 60)

			out = append(out, RuleMatch{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Category:    rule.Category,
				Level:       level,
				Confidence:  score,
				Offset:      baseOffset + start,
				Length:      int(end - start),
				Preview:     preview,
				Context:     ctxSnip,
				Value:       string(matchBytes),
				PatternDesc: pat.Description,
			})
		}
	}
	return out
}

// ─── Distance-weighted context window scoring ─────────────────────────────────
//
// Kỹ thuật Context Window giảm False Positive bằng cách:
//   1. Tìm keyword của rule trong vùng xung quanh regex match
//   2. Tính boost tỉ lệ nghịch với khoảng cách (gần hơn → boost cao hơn)
//   3. Tổng hợp nhiều keyword → cộng dồn nhưng có trần (cap)
//
// Ví dụ minh họa:
//   "Visa 4532015112830366 ngày hết hạn 12/26"
//              ^match     ^keyword "ngày hết hạn" tại distance=5  → Zone 1 → boost +0.15
//
//   "... lorem ipsum ... 4532015112830366 ... thanh toán ... Visa ..."
//                        ^match               ^keyword "Visa" tại distance=25 → Zone 2 → boost +0.10

// ContextZone là vùng khoảng cách với boost tương ứng.
type ContextZone struct {
	MaxDist   int     // Khoảng cách tối đa (bytes) của zone này
	PrimBoost float64 // Boost cho primary keyword trong zone
	SecBoost  float64 // Boost cho secondary keyword trong zone
}

// contextZones định nghĩa 3 vùng khoảng cách với mức boost giảm dần.
// Tham chiếu từ đặc tả người dùng: 20 byte = cao nhất, 50 byte = trung bình.
var contextZones = []ContextZone{
	{MaxDist: 20, PrimBoost: 0.15, SecBoost: 0.07}, // Zone 1: keyword ngay cạnh (trong câu)
	{MaxDist: 50, PrimBoost: 0.10, SecBoost: 0.05}, // Zone 2: keyword trong câu gần
	{MaxDist: 200, PrimBoost: 0.05, SecBoost: 0.02}, // Zone 3: keyword cùng đoạn văn
	// Ngoài maxDist của Zone 3 (hoặc contextWindow): boost = 0
}

// maxTotalBoost là tổng boost tối đa từ keyword context, dù có bao nhiêu keyword.
const maxTotalBoost = 0.30

// distanceWeightedBoost tính tổng boost dựa trên khoảng cách keyword đến match.
//
// Thuật toán:
//  1. Với mỗi keyword hit của ruleID trong chunk
//  2. Tính khoảng cách từ keyword đến match [start, end)
//  3. Nếu khoảng cách ≤ contextWindow: tìm zone phù hợp → cộng boost tương ứng
//  4. Clamp tổng boost tại maxTotalBoost
//
// Zero-copy: chỉ làm việc với HitMap đã có sẵn (không tạo slice mới).
// Gọi từ hot path → không allocate memory.
func distanceWeightedBoost(hits HitMap, ruleID string, matchStart, matchEnd int64, contextWindow int) float64 {
	kwHits := hits[ruleID]
	if len(kwHits) == 0 {
		return 0
	}

	var total float64
	for _, hit := range kwHits {
		dist := int(kwDistance(hit.Offset, matchStart, matchEnd))
		if dist > contextWindow {
			continue // keyword ngoài cửa sổ → không tính
		}

		// Tìm zone phù hợp cho khoảng cách này
		boost := zoneBoost(dist, hit.Primary)
		total += boost

		// Early exit: đã đạt trần boost → không cần xét tiếp
		if total >= maxTotalBoost {
			return maxTotalBoost
		}
	}
	return minF(total, maxTotalBoost)
}

// zoneBoost trả về boost value cho một keyword ở khoảng cách dist.
// primary=true → dùng PrimBoost; primary=false → dùng SecBoost.
func zoneBoost(dist int, primary bool) float64 {
	for _, zone := range contextZones {
		if dist <= zone.MaxDist {
			if primary {
				return zone.PrimBoost
			}
			return zone.SecBoost
		}
	}
	return 0 // vượt quá tất cả các zone
}

// ContextWindowExplain trả về chuỗi mô tả cách tính boost cho một match cụ thể.
// Dùng cho debugging và audit log — không gọi trong hot path.
func ContextWindowExplain(hits HitMap, ruleID string, matchStart, matchEnd int64, contextWindow int) string {
	kwHits := hits[ruleID]
	if len(kwHits) == 0 {
		return "no keyword hits → boost=0.00"
	}

	result := make([]byte, 0, 128)
	result = append(result, "keyword context: "...)
	var total float64
	for i, hit := range kwHits {
		dist := int(kwDistance(hit.Offset, matchStart, matchEnd))
		if dist > contextWindow {
			continue
		}
		boost := zoneBoost(dist, hit.Primary)
		total += boost
		if i > 0 {
			result = append(result, ", "...)
		}
		zone := zoneNumber(dist)
		kwType := "sec"
		if hit.Primary {
			kwType = "pri"
		}
		result = append(result, []byte(
			hit.Keyword+
				"@dist="+itoa(dist)+
				"[zone"+itoa(zone)+","+kwType+
				",+"+ftoa2(boost)+"]",
		)...)
	}
	result = append(result, []byte(" → total="+ftoa2(minF(total, maxTotalBoost)))...)
	return string(result)
}

// zoneNumber trả về số zone (1, 2, 3) cho khoảng cách dist.
func zoneNumber(dist int) int {
	for i, zone := range contextZones {
		if dist <= zone.MaxDist {
			return i + 1
		}
	}
	return 0
}

// itoa chuyển int sang string (không dùng fmt để tránh alloc trong explain).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := 19
	for n > 0 {
		buf[pos] = byte('0' + n%10)
		n /= 10
		pos--
	}
	return string(buf[pos+1:])
}

// ftoa2 chuyển float64 sang string với 2 chữ số thập phân.
func ftoa2(f float64) string {
	// Tránh import "fmt" / "strconv" trong hot path
	i := int(f * 100)
	if i < 0 {
		i = 0
	}
	hi := i / 100
	lo := i % 100
	loStr := itoa(lo)
	if len(loStr) < 2 {
		loStr = "0" + loStr
	}
	return itoa(hi) + "." + loStr
}

// ─── Validators ───────────────────────────────────────────────────────────────

// validatorFuncs ánh xạ tên validator (từ YAML) sang hàm kiểm tra.
// Thêm validator mới ở đây mà không cần sửa code ở nơi khác.
var validatorFuncs = map[string]func([]byte) bool{
	"luhn":           luhnCheck,
	"vn_cccd_prefix": vnCCCDPrefixCheck,
	"vn_bank_prefix": vnBankPrefixCheck,
}

// applyValidators chạy tất cả validators được khai báo cho pattern.
// Trả về (passed=true, enforced=true) nếu tất cả đều pass.
// Trả về (passed=false, enforced=true) nếu BẤT KỲ validator nào fail.
// Trả về (false, false) nếu không có validator nào được nhận dạng.
func applyValidators(b []byte, validators []string) (passed, enforced bool) {
	for _, v := range validators {
		fn, ok := validatorFuncs[v]
		if !ok {
			continue
		}
		enforced = true
		if !fn(b) {
			return false, true // fail ngay lập tức — hard reject
		}
	}
	if enforced {
		passed = true
	}
	return passed, enforced
}

// luhnCheck kiểm tra chuỗi byte (có thể chứa dấu cách, gạch ngang) theo thuật toán Luhn.
//
// Thuật toán Luhn (ISO/IEC 7812):
//  1. Tách ra chỉ lấy chữ số
//  2. Từ phải sang trái, double mỗi digit ở vị trí chẵn
//  3. Nếu double > 9 thì trừ 9
//  4. Tổng mod 10 == 0 → hợp lệ
//
// Áp dụng cho: số thẻ tín dụng (13–19 chữ số), số thẻ ghi nợ.
func luhnCheck(b []byte) bool {
	// Trích xuất chữ số
	var digits [20]byte
	n := 0
	for _, c := range b {
		if c >= '0' && c <= '9' {
			if n >= 20 {
				return false // quá dài
			}
			digits[n] = c - '0'
			n++
		}
	}
	if n < 13 || n > 19 {
		return false // độ dài không hợp lệ cho thẻ
	}

	var sum int
	for i := 0; i < n; i++ {
		d := int(digits[i])
		// Vị trí tính từ phải: (n-1-i). Nếu chẵn (0, 2, 4...) → double.
		if (n-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func vnCCCDPrefixCheck(b []byte) bool {
	digits := digitsOnly(b)
	if len(digits) != 12 {
		return false
	}
	_, ok := vnCCCDProvinceCodes[string(digits[:3])]
	return ok
}

func vnBankPrefixCheck(b []byte) bool {
	digits := digitsOnly(b)
	if len(digits) < 9 || len(digits) > 16 {
		return false
	}
	if len(digits) >= 4 {
		if _, ok := vnBankPrefix4[string(digits[:4])]; ok {
			return true
		}
	}
	if len(digits) >= 3 {
		if _, ok := vnBankPrefix3[string(digits[:3])]; ok {
			return true
		}
	}
	// BIDV thường dùng đầu số 1... trong thực tế triển khai tài khoản nội địa.
	return len(digits) > 0 && digits[0] == '1'
}

func digitsOnly(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return out
}

var vnCCCDProvinceCodes = map[string]struct{}{
	"001": {}, "002": {}, "004": {}, "006": {}, "008": {}, "010": {}, "011": {}, "012": {}, "014": {},
	"015": {}, "017": {}, "019": {}, "020": {}, "022": {}, "024": {}, "025": {}, "026": {}, "027": {},
	"030": {}, "031": {}, "033": {}, "034": {}, "035": {}, "036": {}, "037": {}, "038": {}, "040": {},
	"042": {}, "044": {}, "045": {}, "046": {}, "048": {}, "049": {}, "051": {}, "052": {}, "054": {},
	"056": {}, "058": {}, "060": {}, "062": {}, "064": {}, "066": {}, "067": {}, "068": {}, "070": {},
	"072": {}, "074": {}, "075": {}, "077": {}, "079": {}, "080": {}, "082": {}, "083": {}, "084": {},
	"086": {}, "087": {}, "089": {}, "091": {}, "092": {}, "093": {}, "094": {}, "095": {}, "096": {},
}

var vnBankPrefix4 = map[string]struct{}{
	"1014": {}, "1015": {}, // Vietcombank
	"9704": {}, "9701": {}, "9702": {}, "9703": {}, "9705": {}, "9706": {}, "9707": {}, "9708": {}, "9709": {},
}

var vnBankPrefix3 = map[string]struct{}{
	"211": {}, // BIDV branch routing pattern
	"122": {}, // Agribank pattern
	"340": {}, // Vietinbank pattern
	"502": {}, // Techcombank pattern
}

func shouldSkipPostFilter(chunk []byte, start, end int, ruleID string, match []byte) bool {
	if isCommentedLine(chunk, start) {
		return true
	}

	lower := strings.ToLower(string(match))
	switch ruleID {
	case "credentials_001":
		placeholders := []string{
			"your_api_key_here", "your-password", "your_password", "yourpassword",
			"changeme", "placeholder", "dummy", "example", "xxxxx", "***", "${",
		}
		for _, p := range placeholders {
			if strings.Contains(lower, p) {
				return true
			}
		}
	case "email_001":
		if strings.HasPrefix(lower, "noreply@") || strings.HasPrefix(lower, "no-reply@") ||
			strings.HasPrefix(lower, "donotreply@") || strings.HasPrefix(lower, "mailer-daemon@") ||
			strings.HasPrefix(lower, "bounce@") {
			return true
		}
	}

	_ = end
	return false
}

func adjustLevelPostFilter(ruleID string, match []byte, level ClassificationLevel) ClassificationLevel {
	if ruleID != "email_001" {
		return level
	}
	lower := strings.ToLower(string(match))
	if strings.HasSuffix(lower, "@vnpt.vn") || strings.HasSuffix(lower, "@vnpt-i.vn") || strings.HasSuffix(lower, "@vnptit.vn") {
		if level > Internal {
			return Internal // whitelist: không report L3/L4 cho mail nội bộ kỹ thuật
		}
	}
	return level
}

func isCommentedLine(chunk []byte, start int) bool {
	if start <= 0 || start > len(chunk) {
		return false
	}
	lineStart := bytes.LastIndexByte(chunk[:start], '\n') + 1
	prefix := strings.TrimSpace(string(chunk[lineStart:start]))
	return strings.HasPrefix(prefix, "#") || strings.HasPrefix(prefix, "//") || strings.HasPrefix(prefix, ";")
}

// ─── Escalation ───────────────────────────────────────────────────────────────

// checkEscalation kiểm tra xem có keyword escalation nào trong ±300 byte
// quanh match không; nếu có, nâng cấp level lên rule.Escalation.EscalateTo.
func checkEscalation(chunk []byte, start, end int, rule *Rule, current ClassificationLevel) ClassificationLevel {
	ctxStart := maxI(0, start-300)
	ctxEnd := minI(len(chunk), end+300)
	window := bytes.ToLower(chunk[ctxStart:ctxEnd])

	for _, kw := range rule.Escalation.Keywords {
		if bytes.Contains(window, bytes.ToLower([]byte(kw))) {
			escalated := ParseLevel(rule.Escalation.EscalateTo)
			if escalated > current {
				return escalated
			}
		}
	}
	return current
}

// ─── Preview / Context helpers ───────────────────────────────────────────────

// maskPreview trả về preview đã mask: giữ 4 char đầu và 4 char cuối,
// thay phần giữa bằng "****". Ví dụ: "4111111111111111" → "4111****1111"
func maskPreview(b []byte) string {
	s := string(b)
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// extractContext lấy đoạn văn bản ±radius byte xung quanh match [start, end).
// Dùng để hiển thị ngữ cảnh trong kết quả scan.
func extractContext(chunk []byte, start, end, radius int) string {
	ctxStart := maxI(0, start-radius)
	ctxEnd := minI(len(chunk), end+radius)
	return string(chunk[ctxStart:ctxEnd])
}

// ─── Math helpers ─────────────────────────────────────────────────────────────

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
