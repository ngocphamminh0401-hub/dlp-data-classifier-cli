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
//	if validator_pass: score = min(score + 0.12, 0.99)  // additive, giữ relative ranking
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
			validated := false
			if len(pat.Validators) > 0 {
				passed, enforced := applyValidators(matchBytes, pat.Validators)
				if enforced && !passed {
					continue // false positive đã bị lọc bởi thuật toán (vd: số thẻ sai Luhn)
				}
				if enforced && passed {
					validated = true
					// Additive boost thay vì hard override — giữ relative ranking giữa các IIN.
					// Visa/Napas đã có base cao → vẫn đạt 0.99; UnionPay (IIN rộng hơn)
					// dừng ở ~0.96, phản ánh đúng FP risk cao hơn.
					score = minF(score+0.12, 0.99)
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
				Validated:   validated,
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
	{MaxDist: 20, PrimBoost: 0.15, SecBoost: 0.07},  // Zone 1: keyword ngay cạnh (trong câu)
	{MaxDist: 50, PrimBoost: 0.10, SecBoost: 0.05},  // Zone 2: keyword trong câu gần
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

// bareDiseaseNames: tên bệnh trần trụi (health_001, HEALTH_GENERAL, không
// nhãn "Chẩn đoán:") — dùng trong 2 post-filter riêng biệt: (1) khớp nhầm
// cột "Nhóm thuốc" trong danh mục thuốc/vật tư y tế, (2) khớp nhầm thống kê
// ca bệnh ẩn danh trong biên bản họp giao ban khoa. Xem chi tiết tại từng
// điểm dùng trong shouldSkipPostFilter (case "health_001").
var bareDiseaseNames = map[string]bool{
	"ung thư": true, "cancer": true, "u ác tính": true, "malignant": true,
	"tiểu đường": true, "diabetes": true, "tim mạch": true, "cardiovascular": true,
	"đột quỵ": true, "stroke": true, "thận mãn": true, "chronic kidney": true,
	"suy thận": true, "renal failure": true, "lao phổi": true, "tuberculosis": true,
}

// placeholderSensitiveRules: rule khớp GIÁ TRỊ PII/tài chính cụ thể — nơi
// annotation "(ví dụ)"/"(mẫu điền)" ngay sau match có ý nghĩa "giá trị này
// giả". KHÔNG gồm rule khớp từ vựng/chủ đề (business_internal_001,
// watermark_001, healthcare_internal_business_001, hr_internal_business_001,
// fraud_investigation_001, classified_doc_*, insurance_context_001...) —
// với nhóm đó, annotation "ví dụ" đứng gần chỉ nói lên CÁC GIÁ TRỊ KHÁC
// trong văn bản là giả, không phủ nhận việc từ vựng đó THẬT SỰ xuất hiện
// (VD "biểu mẫu" trong tiêu đề vẫn là bằng chứng thật "đây là biểu mẫu").
var placeholderSensitiveRules = map[string]bool{
	"vn_id_001":             true,
	"passport_001":          true,
	"social_insurance_001":  true,
	"dob_001":               true,
	"phone_001":             true,
	"email_001":             true,
	"vn_name_001":           true,
	"bank_account_001":      true,
	"credit_card_001":       true,
	"cvv_001":               true,
	"otp_auth_001":          true,
	"swift_bic_001":         true,
	"iban_001":              true,
	"income_001":            true,
	"tax_code_business_001": true,
	"tax_code_personal_001": true,
	"health_001":            true,
	"biometric_001":         true,
	"location_tracking_001": true,
}

func shouldSkipPostFilter(chunk []byte, start, end int, ruleID string, match []byte) bool {
	if isCommentedLine(chunk, start) {
		return true
	}

	// Placeholder/ví dụ minh họa — CHỈ áp dụng cho rule khớp GIÁ TRỊ PII/tài
	// chính cụ thể (số CCCD, ngày sinh, SĐT, email, số tài khoản...), KHÔNG
	// áp dụng cho rule khớp TỪ VỰNG/chủ đề văn bản (business_internal_001,
	// watermark_001, healthcare_internal_business_001...). Lý do: với rule
	// giá trị, "(ví dụ)" ngay sau nghĩa là GIÁ TRỊ đó giả — nên loại. Với
	// rule từ vựng, "biểu mẫu"/"quy trình" xuất hiện là bằng chứng THẬT về
	// LOẠI văn bản dù giá trị PII khác trong cùng văn bản là giả — áp dụng
	// nhầm sẽ xóa luôn tín hiệu "đây là biểu mẫu/tài liệu nội bộ" hợp lệ.
	// Xác nhận qua health_int_00748.docx: tiêu đề "BIỂU MẪU DÙNG ĐÀO TẠO -
	// VÍ DỤ MINH HỌA..." khiến match "biểu mẫu" của business_internal_001
	// (rule từ vựng) bị xóa nhầm nếu áp dụng chung, làm file tụt hẳn xuống
	// PUBLIC thay vì INTERNAL đúng.
	if placeholderSensitiveRules[ruleID] {
		// Xác nhận qua health_int_00001.docx: "Ngày sinh: 01/01/1990 (ví
		// dụ)", "Số CMND/CCCD: 012345678 (ví dụ minh họa)". RE2 không hỗ trợ
		// lookahead dài nên dùng post-filter kiểm tra byte NGAY SAU match.
		//
		// ĐÃ SỬA (vòng 2): bản gốc yêu cầu "(" NGAY TRƯỚC cụm từ (VD "(ví
		// dụ") — bỏ sót biến thể có từ chen giữa. Xác nhận qua health_int_
		// 00748.docx: "Số CMND/CCCD: 012345678 (DỮ LIỆU ví dụ, không dùng số
		// thật)" — dấu "(" đứng trước "dữ liệu", không phải trực tiếp trước
		// "ví dụ" — check cũ (Contains "(ví dụ") không khớp dù rõ ràng là
		// placeholder. Bỏ yêu cầu "(" liền kề; nới cửa sổ 20→50 byte; thêm
		// "mẫu điền"/"không dùng số thật"/"dữ liệu ví dụ" (cùng file: "Số
		// thẻ BHYT: XX-X-XX-XXX-XXXXX (mẫu điền)"). KHÔNG dùng bare "mẫu"/
		// "mau" — quá chung chung, dễ khớp nhầm văn bản có PII thật tình cờ
		// nhắc "mẫu" chỗ khác (VD "báo cáo mẫu", "theo mẫu quy định").
		afterEnd := minI(len(chunk), end+50)
		after := strings.ToLower(string(chunk[end:afterEnd]))
		placeholderMarkers := []string{
			"ví dụ", "vi du", "minh họa", "minh hoa", "mẫu điền", "mau dien",
			"không dùng số thật", "khong dung so that", "không phải số thật", "khong phai so that",
			"dữ liệu ví dụ", "du lieu vi du", "(demo", "(example", "(sample",
		}
		for _, marker := range placeholderMarkers {
			if strings.Contains(after, marker) {
				return true
			}
		}
	}

	lower := strings.ToLower(string(match))
	// normLower: gộp mọi khoảng trắng liên tiếp (kể cả \n do PDF tách dòng
	// giữa cụm từ, VD "hồ sơ\nbệnh án") thành 1 dấu cách — dùng cho so sánh
	// CHÍNH XÁC/tra map bên dưới, tránh bỏ sót do lower còn giữ nguyên \n.
	// Xác nhận qua health_int_00156.pdf (healthcare__internal, ground truth
	// INTERNAL): match "hồ sơ\nbệnh án" không khớp lower=="hồ sơ bệnh án".
	normLower := strings.Join(strings.Fields(lower), " ")
	switch ruleID {
	case "health_001":
		// "sản khoa" (HEALTH_RESTRICTED, SECRET không gate — dành cho nội
		// dung sinh sản nhạy cảm) cũng khớp nhầm TÊN CHUYÊN KHOA/CHỨC DANH
		// bác sĩ ký tên (VD "Chức danh: Bác sĩ sản khoa", "Khoa Sản khoa")
		// — không liên quan nội dung sản khoa nhạy cảm của bệnh nhân, chỉ
		// là tên chuyên môn người ký. Xác nhận qua health_conf_00009/00108/
		// 00125/00134.docx (healthcare__confidential, ground truth
		// CONFIDENTIAL). RE2 không lookbehind nên loại trừ bằng post-filter:
		// nếu "sản khoa" nằm ngay sau "bác sĩ"/"chức danh"/"chuyên khoa" (≤20
		// byte trước) thì đây là tên chức danh, không phải nội dung nhạy cảm.
		if strings.Contains(lower, "sản khoa") || strings.Contains(lower, "sản   khoa") {
			ctxStart := maxI(0, start-20)
			before := strings.ToLower(string(chunk[ctxStart:start]))
			if strings.Contains(before, "bác sĩ") || strings.Contains(before, "bac si") ||
				strings.Contains(before, "chức danh") || strings.Contains(before, "chuyên khoa") ||
				strings.Contains(before, "chuyen khoa") || strings.Contains(before, "khoa:") {
				return true
			}
		}
		// "tâm thần hoặc tử vong" trong bảng THỜI HẠN LƯU TRỮ hồ sơ bệnh án
		// (VD "Hồ sơ người bệnh tâm thần hoặc tử vong: lưu trữ tối thiểu 20
		// năm") — cụm cố định trong văn bản QUY CHẾ BẢO MẬT liệt kê các NHÓM
		// hồ sơ theo thời hạn lưu trữ, không phải chẩn đoán thật của bệnh nhân
		// cụ thể nào. Xác nhận qua health_int_00616/00627.docx (healthcare__
		// internal, ground truth INTERNAL). Idiom rất hẹp ("tâm thần" đứng
		// ngay trước "hoặc tử vong") — chẩn đoán tâm thần thật sẽ không dùng
		// "hoặc tử vong" làm phương án thay thế, nên an toàn để loại trừ cục
		// bộ (không cần loại cả HEALTH_RESTRICTED nói chung).
		// ĐÃ MỞ RỘNG 2 LẦN: bản gốc chỉ khớp "hoặc tử vong" (20 byte) nhưng
		// thực tế văn bản có nhiều biến thể dài hơn — "tâm thần, tử vong:"
		// (health_int_00028.docx) và "tâm thần, người bệnh tử vong:"
		// (health_int_00063.docx, 27 byte tới "tử vong") — nới cửa sổ lên
		// 45 byte, đủ bao trùm các biến thể liệt kê nhóm hồ sơ theo thời hạn
		// lưu trữ đã gặp, vẫn đủ hẹp để không lẫn văn xuôi chẩn đoán thật.
		if strings.Contains(lower, "tâm thần") || strings.Contains(lower, "tam than") {
			afterEnd2 := minI(len(chunk), end+45)
			after2 := strings.ToLower(string(chunk[end:afterEnd2]))
			if strings.Contains(after2, "tử vong") || strings.Contains(after2, "tu vong") {
				return true
			}
		}
		// Biểu mẫu/template đào tạo trống — xác nhận qua health_int_00001.
		// docx (healthcare__internal, ground truth INTERNAL): tiêu đề "PHIẾU
		// NHẬP VIỆN (DÙNG NỘI BỘ - TEMPLATE ĐÀO TẠO)" + "...không lưu trữ như
		// hồ sơ bệnh án thật" — health_001 vẫn khớp bare "hồ sơ bệnh án"
		// (HEALTH_GENERAL, override CONFIDENTIAL) dù văn bản TỰ KHAI đây là
		// biểu mẫu trống dùng đào tạo, không phải hồ sơ thật. Kiểm tra CẢ
		// CHUNK (không chỉ lân cận match) vì đây là tín hiệu Ở CẤP VĂN BẢN,
		// không phải cục bộ. Loại trừ CÓ CHỦ ĐÍCH các từ khóa HEALTH_RESTRICTED
		// (HIV/AIDS/tâm thần/di truyền/pháp y...) khỏi post-filter này — dù
		// văn bản có gắn nhãn "template đào tạo", 1 chẩn đoán HIV/tâm thần
		// thật (nếu vô tình xuất hiện) vẫn nên giữ SECRET theo đúng chính
		// sách "luôn SECRET không gate" đã thống nhất, không nên bị nới lỏng
		// chỉ vì tiêu đề văn bản.
		if !strings.Contains(lower, "hiv") && !strings.Contains(lower, "aids") &&
			!strings.Contains(lower, "tâm thần") && !strings.Contains(lower, "tam than") &&
			!strings.Contains(lower, "di truyền") && !strings.Contains(lower, "di truyen") &&
			!strings.Contains(lower, "adn") && !strings.Contains(lower, "dna") &&
			!strings.Contains(lower, "sản khoa") && !strings.Contains(lower, "phá thai") &&
			!strings.Contains(lower, "pha thai") && !strings.Contains(lower, "pháp y") &&
			!strings.Contains(lower, "phap y") {
			chunkLower := strings.ToLower(string(chunk))
			if strings.Contains(chunkLower, "template đào tạo") || strings.Contains(chunkLower, "template dao tao") ||
				strings.Contains(chunkLower, "biểu mẫu trống") || strings.Contains(chunkLower, "bieu mau trong") ||
				strings.Contains(chunkLower, "không lưu trữ như") || strings.Contains(chunkLower, "khong luu tru nhu") {
				return true
			}

			// Biên bản họp giao ban khoa — bàn về QUY TRÌNH/CA BỆNH ẨN DANH
			// (không định danh bệnh nhân cụ thể), không phải hồ sơ bệnh án
			// thật. Xác nhận qua health_int_00682/00698.docx (healthcare__
			// internal, ground truth INTERNAL — dataset tự ghi rõ "Không đề
			// cập thông tin cụ thể, định danh cá nhân bệnh nhân"): "tiếp tục
			// tăng cường cập nhật hồ sơ bệnh án điện tử" (bàn quy trình, bare
			// "hồ sơ bệnh án" không nhãn "Chẩn đoán:") và "Có 2 trường hợp
			// bệnh lý phức tạp (...suy thận mạn...)" (thống kê ca bệnh ẨN
			// DANH, không tên bệnh nhân — khớp nhầm nhánh tên bệnh trần trụi
			// vốn nhắm chẩn đoán CÓ định danh). Chỉ loại "hồ sơ bệnh án" bare
			// và tên bệnh trần trụi — KHÔNG loại pattern có nhãn "Chẩn đoán:"
			// (nhãn rõ ràng vẫn là tín hiệu hồ sơ thật đáng tin hơn).
			//
			// "Quy chế bảo mật hồ sơ bệnh án" — VĂN BẢN CHÍNH SÁCH quy định
			// cách lưu trữ/truy cập/xử lý vi phạm đối với hồ sơ bệnh án nói
			// chung (không nhắc bệnh nhân/chẩn đoán cụ thể nào), khiến bare
			// "hồ sơ bệnh án"/"bệnh án" lặp lại 10+ lần trong toàn văn bản.
			// Xác nhận qua health_int_00616/00627.docx (healthcare__internal,
			// ground truth INTERNAL).
			// MỞ RỘNG: "quy định bảo mật"/"tài liệu đào tạo"/"hội thảo chuyên
			// môn/đề" — xác nhận qua health_int_00572.docx (healthcare__
			// internal, ground truth INTERNAL): tiêu đề "TÀI LIỆU ĐÀO TẠO NỘI
			// BỘ..." có mục "Các điểm lưu ý trong quy định bảo mật thông tin
			// bệnh án theo Nghị định 13/2023/NĐ-CP" — tham chiếu luật chung,
			// không phải hồ sơ bệnh nhân cụ thể.
			if normLower == "hồ sơ bệnh án" || normLower == "bệnh án" || bareDiseaseNames[normLower] {
				if strings.Contains(chunkLower, "biên bản họp giao ban") || strings.Contains(chunkLower, "bien ban hop giao ban") ||
					strings.Contains(chunkLower, "họp giao ban khoa") || strings.Contains(chunkLower, "hop giao ban khoa") ||
					strings.Contains(chunkLower, "quy chế bảo mật") || strings.Contains(chunkLower, "quy che bao mat") ||
					strings.Contains(chunkLower, "quy định bảo mật") || strings.Contains(chunkLower, "quy dinh bao mat") ||
					strings.Contains(chunkLower, "tài liệu đào tạo") || strings.Contains(chunkLower, "tai lieu dao tao") ||
					strings.Contains(chunkLower, "hội thảo chuyên môn") || strings.Contains(chunkLower, "hoi thao chuyen mon") ||
					strings.Contains(chunkLower, "hội thảo chuyên đề") || strings.Contains(chunkLower, "hoi thao chuyen de") ||
					strings.Contains(chunkLower, "đào tạo chuyên môn") || strings.Contains(chunkLower, "dao tao chuyen mon") {
					return true
				}
			}

			// Tên bệnh trần trụi (HEALTH_GENERAL) khớp nhầm trong HỘI THẢO/
			// ĐÀO TẠO CHUYÊN MÔN NỘI BỘ bàn về PHÁC ĐỒ ĐIỀU TRỊ chung của 1
			// loại bệnh (VD "Cập nhật phác đồ điều trị tăng huyết áp" nhắc
			// "tim mạch"/"suy thận" như bối cảnh dịch tễ/biến chứng chung,
			// không phải chẩn đoán của bệnh nhân cụ thể nào) — xác nhận qua
			// health_int_00635/00640.docx (healthcare__internal, ground
			// truth INTERNAL). Chỉ loại tên bệnh trần trụi, không loại pattern
			// có nhãn "Chẩn đoán:" (vẫn có thể là chẩn đoán ca bệnh minh họa
			// trong thảo luận, giữ nguyên tín hiệu).
			if bareDiseaseNames[normLower] &&
				(strings.Contains(chunkLower, "hội thảo chuyên môn") || strings.Contains(chunkLower, "hoi thao chuyen mon") ||
					strings.Contains(chunkLower, "hội thảo chuyên đề") || strings.Contains(chunkLower, "hoi thao chuyen de") ||
					strings.Contains(chunkLower, "đào tạo chuyên môn") || strings.Contains(chunkLower, "dao tao chuyen mon")) {
				return true
			}

			// "Chẩn đoán:" đứng TRẦN (nhãn tiêu đề mục lục "Định nghĩa và
			// chẩn đoán:" trong tài liệu đào tạo, ngay sau là xuống dòng/gạch
			// đầu dòng khác — KHÔNG có giá trị chẩn đoán thật đi kèm ngay sau
			// dấu ":") trong hội thảo/đào tạo chuyên môn — xác nhận qua
			// health_int_00640.docx (healthcare__internal, ground truth
			// INTERNAL): "2.1. Định nghĩa và chẩn đoán:\n- Đái tháo đường...".
			if (normLower == "chẩn đoán:" || normLower == "chẩn đoán :" || normLower == "chẩn đoán=") &&
				(strings.Contains(chunkLower, "hội thảo chuyên môn") || strings.Contains(chunkLower, "hoi thao chuyen mon") ||
					strings.Contains(chunkLower, "hội thảo chuyên đề") || strings.Contains(chunkLower, "hoi thao chuyen de") ||
					strings.Contains(chunkLower, "đào tạo chuyên môn") || strings.Contains(chunkLower, "dao tao chuyen mon")) {
				afterEnd3 := minI(len(chunk), end+3)
				after3 := string(chunk[end:afterEnd3])
				if strings.HasPrefix(strings.TrimLeft(after3, " \t"), "\n") {
					return true
				}
			}

			// "Khám lâm sàng"/"phiếu khám sức khỏe"/"phân loại sức khỏe"/"kết
			// luận của bác sĩ"/"kết quả cận lâm sàng" — TÊN BƯỚC quy trình
			// khám bệnh chung (VD "Bước 3: Bác sĩ thăm hỏi, khám lâm sàng,
			// chỉ định xét nghiệm..."), không phải hồ sơ khám của bệnh nhân
			// cụ thể nào. Xác nhận qua health_int_00071/00611.docx
			// (healthcare__internal, ground truth INTERNAL — cả 2 là "Quy
			// trình tiếp nhận/vận hành khoa/phòng khám"). Chỉ loại khi match
			// TRÙNG KHỚP CHÍNH XÁC (không phải cụm dài hơn có định danh bệnh
			// nhân đi kèm) và chunk là văn bản QUY TRÌNH (không phải hồ sơ
			// khám thật).
			if (normLower == "khám lâm sàng" || normLower == "phiếu khám sức khỏe" ||
				normLower == "phân loại sức khỏe" || normLower == "kết luận của bác sĩ" ||
				normLower == "kết quả cận lâm sàng") &&
				(strings.Contains(chunkLower, "quy trình tiếp nhận") || strings.Contains(chunkLower, "quy trinh tiep nhan") ||
					strings.Contains(chunkLower, "quy trình vận hành") || strings.Contains(chunkLower, "quy trinh van hanh") ||
					strings.Contains(chunkLower, "quy trình khám bệnh") || strings.Contains(chunkLower, "quy trinh kham benh")) {
				return true
			}

			// Tên bệnh thông thường (HEALTH_GENERAL, bare không nhãn "Chẩn
			// đoán:") khớp nhầm CỘT PHÂN LOẠI THUỐC trong danh mục thuốc/vật
			// tư y tế bệnh viện — xác nhận qua health_int_00702.docx
			// (healthcare__internal, ground truth INTERNAL): bảng "Số thứ
			// tự | Tên thuốc | ... | Nhóm thuốc" có giá trị cột "Tim mạch"
			// (nhóm điều trị của THUỐC, không phải chẩn đoán của BỆNH NHÂN).
			// Không dùng post-filter khoảng cách (proximity) vì header cột
			// "Nhóm thuốc" chỉ xuất hiện 1 LẦN ở đầu bảng, cách xa hàng dữ
			// liệu hàng chục/hàng trăm byte — kiểm tra CẢ CHUNK thay vì lân
			// cận. Chỉ áp dụng khi match TRÙNG KHỚP CHÍNH XÁC 1 trong các từ
			// bare disease-name (không phải cụm dài hơn như "Chẩn đoán: ung
			// thư" — cụm đó có nhãn rõ ràng, không nên bị loại).
			if bareDiseaseNames[normLower] &&
				(strings.Contains(chunkLower, "danh mục thuốc") || strings.Contains(chunkLower, "danh muc thuoc") ||
					strings.Contains(chunkLower, "nhóm thuốc") || strings.Contains(chunkLower, "nhom thuoc") ||
					strings.Contains(chunkLower, "vật tư y tế") || strings.Contains(chunkLower, "vat tu y te")) {
				return true
			}
		}
	case "classified_doc_001":
		// "tối mật" dùng làm TRẠNG TỪ mô tả mức độ nghiêm ngặt lưu trữ NỘI BỘ
		// tự đặt ra ("lưu trữ tối mật theo quy định nội bộ") — không phải
		// NHÃN PHÂN LOẠI tài liệu mật nhà nước thật (khác "TỐI MẬT" đứng độc
		// lập làm watermark/tiêu đề). Cùng loại lỗi với "bảo mật tuyệt đối"
		// (đã loại trong keywords, xem comment ORG-001 phía trên) — ngôn ngữ
		// tự khai nghiêm ngặt, không phải nhãn mật thật. Xác nhận qua
		// health_int_00429.docx (healthcare__internal, ground truth INTERNAL).
		if strings.Contains(lower, "tối mật") || strings.Contains(lower, "toi mat") {
			afterEnd4 := minI(len(chunk), end+30)
			after4 := strings.ToLower(string(chunk[end:afterEnd4]))
			if strings.Contains(after4, "quy định nội bộ") || strings.Contains(after4, "quy dinh noi bo") ||
				strings.Contains(after4, "quy chế nội bộ") || strings.Contains(after4, "quy che noi bo") {
				return true
			}
		}
	case "bank_account_001":
		// Số "Mã số doanh nghiệp:"/"Mã số thuế:" của TỔ CHỨC (10 chữ số, công
		// khai trên cổng đăng ký doanh nghiệp quốc gia) trùng định dạng số tài
		// khoản 9-14 số. exclude_if_no_keywords chỉ kiểm tra keyword có mặt
		// TRONG CẢ CHUNK (không phải gần match cụ thể — xem HitMap.HasRule),
		// nên 1 lần nhắc "tài khoản" ở đoạn khác (VD điều khoản thanh toán)
		// đủ để giữ match này dù số thật ra là mã số doanh nghiệp/thuế, không
		// liên quan tài khoản ngân hàng — xác nhận qua fin_int_00298.docx
		// (finance_banking__internal, hợp đồng B2B giữa 2 pháp nhân). RE2
		// không hỗ trợ lookbehind nên loại trừ bằng post-filter kiểm tra 40
		// byte ngay trước match.
		ctxStart := maxI(0, start-40)
		before := strings.ToLower(string(chunk[ctxStart:start]))
		if strings.Contains(before, "mã số doanh nghiệp") || strings.Contains(before, "mã số thuế") ||
			strings.Contains(before, "ma so doanh nghiep") || strings.Contains(before, "ma so thue") {
			return true
		}
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
		// System/department emails in public documents are not personal data.
		systemPrefixes := []string{
			"noreply@", "no-reply@", "donotreply@", "do-not-reply@", "mailer-daemon@", "bounce@",
			"info@", "contact@", "support@", "help@", "admin@", "administrator@",
			"hotline@", "cskh@", "dichvu@", "dịchvụ@", "thongbao@", "thông-bao@",
			"newsletter@", "marketing@", "sales@", "pr@", "media@",
			"webmaster@", "postmaster@", "unsubscribe@", "listserv@",
			"announce@", "notification@", "alert@", "system@", "robot@", "bot@",
			"no.reply@", "do.not.reply@",
		}
		for _, prefix := range systemPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
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
