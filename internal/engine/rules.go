// Package engine — rule loading and compilation from YAML rule files.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseLevel maps level string to ClassificationLevel.
func ParseLevel(s string) ClassificationLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INTERNAL":
		return Internal
	case "CONFIDENTIAL":
		return Confidential
	case "SECRET", "RESTRICTED":
		return Secret
	default:
		return Public
	}
}

// LevelString returns the string name of a ClassificationLevel.
func LevelString(l ClassificationLevel) string {
	switch l {
	case Internal:
		return "INTERNAL"
	case Confidential:
		return "CONFIDENTIAL"
	case Secret:
		return "RESTRICTED"
	default:
		return "PUBLIC"
	}
}

// RulePattern is a single regex pattern within a rule definition.
type RulePattern struct {
	Regex           string   `yaml:"regex"`
	Description     string   `yaml:"description"`
	Confidence      float64  `yaml:"confidence"`
	ContextRequired bool     `yaml:"context_required"`
	Validators      []string `yaml:"validators"`
	OverrideLevel   string   `yaml:"override_level"`

	// RequireKeywordWithin: nếu >0 (và ContextRequired=true), đòi hỏi keyword
	// PRIMARY của rule phải nằm trong khoảng byte này QUANH TỪNG MATCH cụ thể
	// — thay cho check mặc định của ContextRequired (chỉ cần keyword có mặt
	// BẤT KỲ ĐÂU trong chunk, xem hits.HasRule). Dùng cho pattern dễ FP như
	// ngày/năm bất kỳ (VD dob_001 pattern MM/DD/YYYY, năm sinh đơn lẻ) — 1
	// dòng "Ngày sinh:" ở đầu tài liệu không nên biến MỌI con số 4 chữ số
	// (1900-2029) trong toàn bộ phần còn lại của chunk thành match. 0 (mặc
	// định) = dùng check chunk-wide cũ, không thay đổi hành vi hiện có.
	RequireKeywordWithin int `yaml:"require_keyword_within"`

	Compiled *regexp.Regexp
}

// RuleKeywords supports both flat []string and {primary:[], secondary:[]} YAML forms.
type RuleKeywords struct {
	Primary   []string
	Secondary []string
}

func (rk *RuleKeywords) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		return value.Decode(&rk.Primary)
	case yaml.MappingNode:
		var s struct {
			Primary   []string `yaml:"primary"`
			Secondary []string `yaml:"secondary"`
		}
		if err := value.Decode(&s); err != nil {
			return err
		}
		rk.Primary = s.Primary
		rk.Secondary = s.Secondary
	}
	return nil
}

// KeywordLogic configures confidence scoring for keyword-only rules.
type KeywordLogic struct {
	MinPrimary           int     `yaml:"min_primary"`
	MinSecondary         int     `yaml:"min_secondary"`
	ConfidencePerKeyword float64 `yaml:"confidence_per_keyword"`
	MaxConfidence        float64 `yaml:"max_confidence"`
}

// FPReduction configures false-positive reduction strategies.
//
// MinContextWindow: khi ExcludeIfNoKeywords=true VÀ MinContextWindow>0, check
// "có keyword của rule" chuyển từ CHUNK-WIDE (hits.HasRule, mặc định khi
// MinContextWindow=0) sang GIỚI HẠN KHOẢNG CÁCH — phải có ≥1 keyword (primary
// hoặc secondary) trong vòng MinContextWindow byte quanh CHÍNH match đó. Đây
// là vế (a) trong quan hệ AND với ProximityWindow (xem Rule.ProximityWindow)
// — chỉ CÓ HIỆU LỰC khi rule đó cũng khai proximity_window (validate ở
// loadRule); rule không khai proximity_window giữ nguyên hành vi chunk-wide
// cũ dù có set MinContextWindow (field này TRƯỚC ĐÂY hoàn toàn không được
// engine đọc — dead field — nên không có rule nào trong ruleset hiện tại lỡ
// phụ thuộc vào việc nó bị bỏ qua).
type FPReduction struct {
	MinContextWindow    int     `yaml:"min_context_window"`
	ExcludeIfNoKeywords bool    `yaml:"exclude_if_no_keywords"`
	LuhnRequired        bool    `yaml:"luhn_required"`
	CVVExpiryBoost      float64 `yaml:"cvv_expiry_boost"`
}

// Escalation elevates classification level when additional keywords are present.
type Escalation struct {
	Keywords   []string `yaml:"keywords"`
	EscalateTo string   `yaml:"escalate_to"`
}

// LevelGate yêu cầu bằng chứng thứ 2 ("corroboration") trước khi giữ nguyên
// level của rule khi level đó KHÔNG được validator xác nhận (Luhn, CCCD prefix...).
//
// Vấn đề chống: "highest-sensitivity-wins" (Lớp 3 của Engine.Scan) mặc định để
// 1 match SECRET đơn lẻ, không validator, không lặp lại quyết định toàn bộ file
// là SECRET — dù bằng chứng chỉ là 1 lần nhắc đến từ khóa (vd: "TỐI MẬT" xuất
// hiện trong tài liệu chính sách nói VỀ phân loại, không phải tài liệu chứa nội
// dung mật thật). Rule càng dùng keyword/regex thuần (không validator) ở level
// cao càng dễ dính lỗi này.
//
// Corroboration coi là đủ nếu MỘT trong các điều kiện sau đúng (trong cùng 1 chunk):
//  1. Có match của CHÍNH rule này đã qua validator (Validated=true).
//  2. Rule này khớp ≥2 lần trong chunk (không còn là "1 lần nhắc đến" đơn lẻ).
//  3. Có match từ rule KHÁC trong cùng chunk đạt level ≥ CONFIDENTIAL (file không
//     "chỉ có duy nhất tín hiệu này" — có bằng chứng độc lập khác hỗ trợ).
//  4. Confidence của CHÍNH match đó ≥ MinConfidenceBypass (nếu rule đặt >0) —
//     xem MinConfidenceBypass bên dưới.
//
// Không đủ corroboration → level của match bị hạ về FallbackLevel.
//
// Rule KHÔNG nên bật cờ này nếu 1 match đơn lẻ ĐÃ LÀ rủi ro thật dù không lặp lại
// (vd: credentials_001 — một API key thật rò rỉ 1 lần vẫn là sự cố nghiêm trọng).
type LevelGate struct {
	RequireCorroboration bool   `yaml:"require_corroboration"`
	FallbackLevel        string `yaml:"fallback_level"`

	// AppliesToPatterns/ExemptPatterns giới hạn gate chỉ áp dụng cho MỘT SỐ
	// pattern cụ thể của rule (tham chiếu "pattern_N", 1-indexed theo thứ tự
	// trong `patterns:` YAML — validate ở loadRule qua parsePatternRef). Dùng
	// khi rule trộn lẫn pattern "dãy số trần" (dễ FP, cần gate) với pattern có
	// cấu trúc đặc trưng riêng (label rõ ràng, prefix, MRZ, checksum... — an
	// toàn hơn, nên miễn gate). Cả hai rỗng (mặc định) = gate áp dụng cho MỌI
	// pattern của rule — không thay đổi hành vi hiện có.
	//
	// Độ ưu tiên: nếu AppliesToPatterns không rỗng, gate CHỈ áp dụng cho
	// pattern có trong danh sách đó; ExemptPatterns luôn loại trừ thêm (kể cả
	// khi đã có trong AppliesToPatterns) — xem LevelGate.AppliesToPattern.
	AppliesToPatterns []string `yaml:"applies_to_patterns"`
	ExemptPatterns    []string `yaml:"exempt_patterns"`

	// MinConfidenceBypass: match có Confidence ≥ ngưỡng này coi như TỰ ĐỦ
	// corroboration, bỏ qua downgrade dù không lặp lại/không có rule khác hỗ
	// trợ. Dùng cho rule mà bản thân 1 match confidence rất cao ĐÃ LÀ bằng
	// chứng đủ mạnh (VD watermark_001: các pattern còn lại sau khi đã loại bỏ
	// pattern chung chung đều là cụm đặc trưng nhiều từ — 1 lần khớp là đủ,
	// không nên bắt lặp lại như dãy số trần/keyword đơn). 0 (mặc định) = tắt,
	// không thay đổi hành vi hiện có (chỉ 3 điều kiện corroboration gốc).
	MinConfidenceBypass float64 `yaml:"min_confidence_bypass"`

	// RequiredCorroborationTags: nếu khai, THAY THẾ 2 điều kiện corroboration
	// mặc định "hasOtherStrongRule" (bất kỳ rule khác ≥ CONFIDENTIAL trong
	// cùng chunk) và "hasFamilyCorroboration" bằng yêu cầu CỤ THỂ hơn: phải
	// có ≥1 match (bất kể RuleID/level của chính match đó) mang 1 trong các
	// tag này. Dùng khi 2 điều kiện mặc định quá LỎNG cho use-case cần bằng
	// chứng xác định (VD: health_001 — chỉ giữ level nếu có định danh cá nhân
	// đi kèm, không phải bất kỳ tín hiệu CONFIDENTIAL+ nào khác trong chunk,
	// vì GDPR Điều 9 chỉ bảo vệ dữ liệu sức khỏe GẮN VỚI 1 cá nhân xác định,
	// không bảo vệ kiến thức y khoa chung). Rỗng (mặc định) = dùng 2 điều kiện
	// mặc định như cũ — không thay đổi hành vi hiện có. Tag tham chiếu tự do
	// (không cố định trong engine như tagCorroborationTags) — rule tự khai
	// Tags cần thiết (VD "personal_identifier" trên vn_name_001/vn_id_001/
	// dob_001) rồi trỏ vào đây.
	RequiredCorroborationTags []string `yaml:"required_corroboration_tags"`

	// StrictTagsOnly: nếu true VÀ RequiredCorroborationTags khai, LOẠI BỎ
	// LUÔN 3 điều kiện corroboration còn lại (validatedByRule, counts>=2,
	// MinConfidenceBypass) — corroborated CHỈ còn = hasRequiredTagCorroboration.
	// Dùng khi counts>=2 (tự lặp lại) KHÔNG phải bằng chứng đáng tin cho rule
	// này — VD insurance_context_001: văn bản điều khoản/quy tắc bảo hiểm
	// PUBLIC bình thường đã dễ dàng nhắc "bồi thường"/"yêu cầu bồi thường" ≥2
	// lần (2 pattern khác nhau khớp cùng 1 cụm), khiến counts>=2 gần như luôn
	// đúng và vô hiệu hóa hoàn toàn RequiredCorroborationTags nếu không loại
	// bỏ — xác nhận qua test trực tiếp trước khi thêm field này. false (mặc
	// định) = giữ hành vi cũ (health_001 vẫn dùng counts>=2 làm 1 trong các
	// điều kiện hợp lệ — "≥2 lần nhắc tên bệnh" LÀ tín hiệu đáng tin cho rule
	// đó, khác insurance_context_001).
	StrictTagsOnly bool `yaml:"strict_tags_only"`

	ParsedFallbackLevel ClassificationLevel
}

// AppliesToPattern báo cáo liệu gate có áp dụng cho pattern ở vị trí patIdx
// (0-indexed, tương ứng RuleMatch.PatternIdx) hay không.
func (lg LevelGate) AppliesToPattern(patIdx int) bool {
	ref := "pattern_" + strconv.Itoa(patIdx+1)
	if len(lg.AppliesToPatterns) > 0 {
		found := false
		for _, a := range lg.AppliesToPatterns {
			if a == ref {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, ex := range lg.ExemptPatterns {
		if ex == ref {
			return false
		}
	}
	return true
}

// NegationFilter phản ứng với từ/cụm phủ định (TriggerWords) trong khoảng
// WindowChars quanh match — bằng chứng phủ định trực tiếp ("không phải tài
// liệu nội bộ", "this email", "access denied"...) mạnh hơn việc chỉ thiếu
// corroboration nên xử lý NGAY tại match, không chờ Step 4.5 (applyLevelGate).
//
// AppliesToPatterns giới hạn filter chỉ áp dụng cho MỘT SỐ pattern cụ thể của
// rule (tham chiếu dạng "pattern_N", N = vị trí 1-indexed trong danh sách
// `patterns:` của YAML — validate ở loadRule). Rỗng (mặc định) = áp dụng cho
// TẤT CẢ pattern của rule.
//
// Action hỗ trợ 2 giá trị:
//   - "downgrade_to_gate": hạ level match về rule.LevelGate.ParsedFallbackLevel.
//     YÊU CẦU rule bật level_gate.require_corroboration=true (validate ở
//     loadRule) — negation_filter là evidence phụ BỔ SUNG cho level_gate.
//     Dùng khi negation chỉ nên hạ xuống mức trung gian, không loại hẳn.
//   - "suppress": loại bỏ match hoàn toàn, không đóng góp vào kết quả rule ở
//     bất kỳ level nào. Dùng khi rule ĐÃ có level_gate riêng cho các pattern
//     khác (fallback chung) — downgrade_to_gate trên 1 pattern cụ thể vẫn có
//     thể vô tình kéo level chung của rule lên qua corroboration ảo, trong khi
//     suppress loại hẳn match khỏi input nên không góp phần vào bất kỳ đánh
//     giá level nào (kể cả corroboration count của các pattern khác).
type NegationFilter struct {
	WindowChars       int      `yaml:"window_chars"`
	TriggerWords      []string `yaml:"trigger_words"`
	Action            string   `yaml:"action"`
	AppliesToPatterns []string `yaml:"applies_to_patterns"`
}

// PlaceholderExclusion loại trừ/giảm confidence các match nhiều khả năng là
// giá trị PLACEHOLDER/VÍ DỤ (SOP, tài liệu hướng dẫn, mã test chuẩn ngành...)
// thay vì dữ liệu nhạy cảm thật. Ba cơ chế độc lập, có thể dùng riêng lẻ:
//
//  1. ValueBlocklistPatterns (hard reject): regex ANCHOR (^...$) kiểm tra
//     trên VALUE trích xuất từ match — xem extractMatchValue trong regex.go
//     (heuristic: phần sau dấu ':'/'=' cuối cùng trong match, hoặc sau
//     khoảng trắng cuối cùng nếu không có ':'/'='). Khớp → loại HOÀN TOÀN,
//     giống validator fail (không tạo match ở bất kỳ level nào).
//  2. KnownTestValues (hard reject, exact match): giá trị CHUẨN HÓA (chỉ giữ
//     chữ số — dùng digitsOnly, xem regex.go) so khớp CHÍNH XÁC với giá trị
//     match đã chuẩn hóa tương tự. Dùng cho số thẻ test công khai của cổng
//     thanh toán (Stripe, VNPay...) — các số này hợp lệ Luhn nên validator
//     thường không loại được; check này chạy SAU validators (xem thứ tự
//     Step 3.5 trong matchAllPatterns) nên coi như "sau khi đã qua Luhn".
//  3. DocContextDiscountKeywords + DocContextDiscountFactor (soft discount):
//     nếu match KHÔNG bị loại bởi 2 cơ chế trên nhưng chunk chứa 1 trong các
//     từ khóa này (hướng dẫn, ví dụ, SOP, template...) → nhân confidence với
//     DocContextDiscountFactor (0 < factor < 1) — chỉ giảm điểm, match vẫn
//     có thể qua ngưỡng nếu vốn đã rất cao, khác 2 cơ chế trên (loại hẳn).
type PlaceholderExclusion struct {
	ValueBlocklistPatterns []string `yaml:"value_blocklist_patterns"`

	// ValueBlocklistFullMatch: true = kiểm ValueBlocklistPatterns trên TOÀN
	// BỘ match (chỉ trim khoảng trắng bao quanh), bỏ qua heuristic tách
	// "value" của extractMatchValue. Dùng cho rule mà match TỰ NÓ là cụm
	// nhiều từ không có label/delimiter rõ ràng (VD vn_name_001: match là cả
	// họ tên "Nguyễn Văn A" — extractMatchValue mặc định tách theo khoảng
	// trắng CUỐI sẽ chỉ lấy "A", làm sai lệch việc so khớp cả cụm họ tên).
	// false (mặc định) = dùng extractMatchValue như trước.
	ValueBlocklistFullMatch bool `yaml:"value_blocklist_full_match"`

	KnownTestValues            []string `yaml:"known_test_values"`
	DocContextDiscountKeywords []string `yaml:"doc_context_discount_keywords"`
	DocContextDiscountFactor   float64  `yaml:"doc_context_discount_factor"`

	CompiledBlocklist    []*regexp.Regexp
	NormalizedTestValues map[string]struct{}
}

// VolumeThreshold là một bậc trong volume escalation: khi số match của rule
// trong CÙNG MỘT FILE đạt MinCount, level được nâng lên EscalateTo.
type VolumeThreshold struct {
	MinCount    int    `yaml:"min_count"`
	EscalateTo  string `yaml:"escalate_to"`
	ParsedLevel ClassificationLevel
}

// VolumeEscalation nâng cấp độ phân loại dựa trên SỐ LẦN một rule khớp trong
// toàn bộ file — phản ánh rủi ro lộ lọt hàng loạt (vd: 500 email trong 1 file
// nghiêm trọng hơn 1 email lẻ), tách biệt với confidence của từng match riêng lẻ.
//
// Thresholds nên khai theo thứ tự MinCount tăng dần trong YAML; engine tự sort
// lại lúc load nên thứ tự trong file không bắt buộc.
type VolumeEscalation struct {
	Thresholds []VolumeThreshold `yaml:"thresholds"`
}

// ProximityWindow là điều kiện BỔ SUNG (AND, không thay thế) cho
// FPReduction.ExcludeIfNoKeywords/MinContextWindow — vế (a) là "có keyword
// trong MinContextWindow byte quanh match" (lưới an toàn rộng, không cần
// cùng câu), vế (b) là ProximityWindow: "có keyword trong MaxChars byte
// quanh match VÀ (nếu SameSentenceRequired) trong CÙNG CÂU với match". Một
// match chỉ pass FP-reduction khi thỏa CẢ HAI vế — xem điểm dùng trong
// regex.go (matchAllPatterns, bước "FP reduction: exclude_if_no_keywords").
//
// Ranh giới câu (xem crossesSentenceBoundary trong regex.go) xử lý riêng dấu
// "." làm separator hàng nghìn/thập phân ("25.000.000") và viết tắt hành
// chính/học thuật VN (TP., Th.S, PGS., GS., ĐH., Cty., Q., P., "Điều 5.") —
// không cắt câu ngây thơ theo mọi dấu chấm, tránh phá hỏng chính các rule số
// tiền/số tài khoản cần bảo vệ nhất.
//
// Chỉ CÓ HIỆU LỰC khi FPReduction.ExcludeIfNoKeywords=true VÀ
// FPReduction.MinContextWindow>0 (validate ở loadRule) — MaxChars=0 (mặc
// định) = tắt hoàn toàn, không ảnh hưởng rule không khai báo field này.
type ProximityWindow struct {
	// MaxChars là khoảng cách tối đa (byte) giữa keyword và match cho vế (b).
	MaxChars int `yaml:"max_chars"`

	// SameSentenceRequired: nếu true, keyword còn phải cùng câu với match
	// (không bị ranh giới kết câu thật cắt ngang). Nếu KHÔNG tìm thấy ranh
	// giới câu nào trong ±100 byte quanh keyword (văn bản dạng bảng/liệt kê
	// không dấu câu chuẩn — sao kê, bảng lương, danh sách khách hàng), bỏ
	// qua yêu cầu này (fallback_on_no_boundary: window) — ưu tiên không mất
	// recall trên dữ liệu dạng bảng.
	SameSentenceRequired bool `yaml:"same_sentence_required"`

	// KeywordScope: "primary" (mặc định) chỉ tính keyword primary, hoặc
	// "primary_or_secondary" tính cả 2 loại.
	KeywordScope string `yaml:"keyword_scope"`

	// FallbackOnNoBoundary: hiện chỉ hỗ trợ "window" (mặc định) — dùng
	// MinContextWindow (vế a) làm lưới dự phòng khi không xác định được ranh
	// giới câu. Field giữ lại để tương thích schema, validate ở loadRule.
	FallbackOnNoBoundary string `yaml:"fallback_on_no_boundary"`
}

// Rule is a loaded and compiled classification rule.
type Rule struct {
	ID           string        `yaml:"id"`
	Name         string        `yaml:"name"`
	Category     string        `yaml:"category"`
	Level        string        `yaml:"level"`
	Weight       float64       `yaml:"weight"`
	Enabled      bool          `yaml:"enabled"`
	Patterns     []RulePattern `yaml:"patterns"`
	Keywords     RuleKeywords  `yaml:"keywords"`
	KeywordLogic KeywordLogic  `yaml:"keyword_logic"`
	FPReduction  FPReduction   `yaml:"false_positive_reduction"`
	Escalation   Escalation    `yaml:"escalation"`

	// VolumeEscalation nâng level theo số lần rule khớp trong toàn file.
	// Rỗng = tắt (mặc định) — không thay đổi hành vi hiện có.
	VolumeEscalation VolumeEscalation `yaml:"volume_escalation"`

	// LevelGate hạ level nếu match không có bằng chứng thứ 2 hỗ trợ.
	// RequireCorroboration=false (mặc định) = tắt — không thay đổi hành vi hiện có.
	LevelGate LevelGate `yaml:"level_gate"`

	// NegationFilter hạ level ngay khi gặp từ/cụm phủ định gần match.
	// TriggerWords rỗng (mặc định) = tắt — không thay đổi hành vi hiện có.
	NegationFilter NegationFilter `yaml:"negation_filter"`

	// PlaceholderExclusion loại trừ/giảm confidence match nhiều khả năng là
	// giá trị placeholder/ví dụ. Rỗng (mặc định) = tắt — không thay đổi hành
	// vi hiện có.
	PlaceholderExclusion PlaceholderExclusion `yaml:"placeholder_exclusion"`

	// ProximityWindow siết false_positive_reduction.exclude_if_no_keywords
	// xuống mức khoảng cách + ranh giới câu thay vì chunk-wide. MaxChars=0
	// (mặc định) = tắt — không thay đổi hành vi hiện có.
	ProximityWindow ProximityWindow `yaml:"proximity_window"`

	// Priority xác định thứ tự đánh giá rule (cao hơn = đánh giá trước).
	// Rule có priority cao hơn được kích hoạt fast-fail sớm hơn.
	// Mặc định 0; các rule quan trọng (credit card, secret key) nên đặt cao.
	Priority int `yaml:"priority"`

	// Tags là các nhãn tùy chỉnh để compound rules tham chiếu.
	// Nếu không đặt, engine tự suy ra từ category + rule ID prefix.
	// Ví dụ: tags: [pii, identity, vn_specific]
	Tags []string `yaml:"tags"`

	// ParsedLevel là giá trị đã parse của trường Level (cached lúc load).
	ParsedLevel ClassificationLevel
}

// CompoundRule elevates classification when multiple categories co-occur.
type CompoundRule struct {
	Name        string
	Conditions  []string
	ResultLevel ClassificationLevel

	// MinComponentLevel ràng buộc: chỉ trigger khi MỖI condition có ít nhất một
	// match ở level >= MinComponentLevel. Dùng để tránh over-classification:
	// email(INTERNAL) + BIC(INTERNAL) không trigger "PII + Financial = SECRET".
	// 0 = không ràng buộc (mọi level đều kích hoạt).
	MinComponentLevel ClassificationLevel

	// ContextConditions: tag PHẢI CÓ MẶT (bất kể level) — kiểm tra RIÊNG,
	// KHÔNG bị ràng buộc bởi MinComponentLevel (vốn áp dụng chung cho toàn
	// bộ Conditions, không hỗ trợ ngưỡng riêng từng điều kiện — xem
	// rules.yaml phần compound "Ethnicity/Religion + X + HR Context").
	// Dùng khi cần 1 điều kiện "thu hẹp phạm vi domain" mà KHÔNG muốn nó bị
	// đòi hỏi cùng ngưỡng level cao như các điều kiện chính (VD: rule
	// catch-all yếu như hr_internal_business_001 thường bị gate hạ xuống
	// PUBLIC/INTERNAL, không bao giờ đạt CONFIDENTIAL — nếu nhét vào
	// Conditions cùng MinComponentLevel:CONFIDENTIAL sẽ vô hiệu hóa hoàn
	// toàn vai trò "đánh dấu đây là tài liệu HR" của nó).
	ContextConditions []string

	// ViolationType là mã vi phạm quy định để trigger workflow riêng
	// (ví dụ: "PCI_DSS_3.3.1", "HIPAA_PHI", "ACCOUNT_TAKEOVER_ENABLER").
	// Rỗng = không có violation type đặc biệt.
	ViolationType string

	// AlertPriority là mức ưu tiên cảnh báo: "CRITICAL" | "HIGH" | "MEDIUM" | "".
	AlertPriority string

	// ExcludeContextPatterns: nếu BẤT KỲ regex nào trong danh sách này khớp
	// TOÀN CHUNK → compound rule này KHÔNG kích hoạt, bất kể Conditions/
	// MinComponentLevel/ContextConditions đã thỏa mãn. Ngược hướng với
	// ContextConditions (đòi hỏi CÓ MẶT) — đây là negative-signal: loại trừ
	// khi phát hiện ngữ cảnh domain khác với domain compound rule nhắm tới.
	//
	// Dùng cho compound "Ethnicity/Religion + Health = SECRET": tài liệu tự
	// ghi nhận over-classify ~100 file trên healthcare vì "Dân tộc" là
	// trường nhân khẩu học thu thập THƯỜNG QUY trong mẫu bệnh án VN (không
	// phải dấu hiệu bất thường), nhưng gỡ compound hẳn gây hồi quy nặng trên
	// hr__top_secret (83.7%→60.2%). ĐÃ THỬ context_conditions:[hr] trước đó
	// (positive-signal theo domain HR) — KHÔNG đủ vì tag "hr" không phải
	// discriminator đáng tin cậy (xem lịch sử ở rules.yaml). ExcludeContextPatterns
	// thử hướng NGƯỢC LẠI: negative-signal theo domain y tế thường quy —
	// chỉ áp riêng cho C14 (không phải cả nhóm C10-C14) để giảm rủi ro hồi
	// quy trên hr.
	//
	// Rỗng (mặc định) = không loại trừ gì, hành vi cũ.
	ExcludeContextPatterns []*regexp.Regexp
}

// RuleSet is the full set of loaded and compiled rules.
type RuleSet struct {
	Rules         []*Rule
	CompoundRules []CompoundRule
}

type masterIndex struct {
	Includes []string `yaml:"includes"`
	Compound []struct {
		Name                   string   `yaml:"name"`
		Conditions             []string `yaml:"conditions"`
		ContextConditions      []string `yaml:"context_conditions"`
		ExcludeContextPatterns []string `yaml:"exclude_context_patterns"`
		ResultLevel            string   `yaml:"result_level"`
		MinComponentLevel      string   `yaml:"min_component_level"`
		ViolationType          string   `yaml:"violation_type"`
		AlertPriority          string   `yaml:"alert_priority"`
	} `yaml:"compound_rules"`
}

// LoadRuleSet reads rules.yaml master index from dir and loads all included rules.
func LoadRuleSet(dir string) (*RuleSet, error) {
	indexPath := filepath.Join(dir, "rules.yaml")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("reading rule index %s: %w", indexPath, err)
	}

	var idx masterIndex
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parsing rule index: %w", err)
	}

	rs := &RuleSet{}
	for _, include := range idx.Includes {
		path := filepath.Join(dir, filepath.FromSlash(include))
		rule, err := loadRule(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", include, err)
		}
		if rule.Enabled {
			rs.Rules = append(rs.Rules, rule)
		}
	}

	for _, cr := range idx.Compound {
		var excludePatterns []*regexp.Regexp
		for _, p := range cr.ExcludeContextPatterns {
			compiled, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("compound rule %q: exclude_context_patterns: bad regex %q: %w", cr.Name, p, err)
			}
			excludePatterns = append(excludePatterns, compiled)
		}
		rs.CompoundRules = append(rs.CompoundRules, CompoundRule{
			Name:                   cr.Name,
			Conditions:             cr.Conditions,
			ContextConditions:      cr.ContextConditions,
			ExcludeContextPatterns: excludePatterns,
			ResultLevel:            ParseLevel(cr.ResultLevel),
			MinComponentLevel:      ParseLevel(cr.MinComponentLevel),
			ViolationType:          cr.ViolationType,
			AlertPriority:          cr.AlertPriority,
		})
	}

	// Sắp xếp rules theo Priority giảm dần: rule quan trọng (credit card,
	// secret key) được đánh giá trước → fast-fail kích hoạt sớm hơn.
	sort.SliceStable(rs.Rules, func(i, j int) bool {
		return rs.Rules[i].Priority > rs.Rules[j].Priority
	})

	return rs, nil
}

// parsePatternRef parses a "pattern_N" reference (1-indexed, matching the
// order of the `patterns:` list in YAML) used by negation_filter.applies_to_patterns.
// Trả về index 0-indexed tương ứng trong Rule.Patterns.
func parsePatternRef(ref string, numPatterns int) (int, error) {
	const prefix = "pattern_"
	if !strings.HasPrefix(ref, prefix) {
		return 0, fmt.Errorf("tham chiếu pattern không hợp lệ %q (phải dạng \"pattern_N\")", ref)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(ref, prefix))
	if err != nil || n < 1 || n > numPatterns {
		return 0, fmt.Errorf("tham chiếu pattern không hợp lệ %q (rule có %d pattern, N phải trong [1,%d])", ref, numPatterns, numPatterns)
	}
	return n - 1, nil
}

func loadRule(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	r.ParsedLevel = ParseLevel(r.Level)

	for i := range r.VolumeEscalation.Thresholds {
		r.VolumeEscalation.Thresholds[i].ParsedLevel = ParseLevel(r.VolumeEscalation.Thresholds[i].EscalateTo)
	}
	sort.SliceStable(r.VolumeEscalation.Thresholds, func(i, j int) bool {
		return r.VolumeEscalation.Thresholds[i].MinCount < r.VolumeEscalation.Thresholds[j].MinCount
	})

	if r.LevelGate.RequireCorroboration {
		r.LevelGate.ParsedFallbackLevel = ParseLevel(r.LevelGate.FallbackLevel)
		for _, ref := range r.LevelGate.AppliesToPatterns {
			if _, err := parsePatternRef(ref, len(r.Patterns)); err != nil {
				return nil, fmt.Errorf("rule %s: level_gate.applies_to_patterns: %w", r.ID, err)
			}
		}
		for _, ref := range r.LevelGate.ExemptPatterns {
			if _, err := parsePatternRef(ref, len(r.Patterns)); err != nil {
				return nil, fmt.Errorf("rule %s: level_gate.exempt_patterns: %w", r.ID, err)
			}
		}
		if r.LevelGate.StrictTagsOnly && len(r.LevelGate.RequiredCorroborationTags) == 0 {
			return nil, fmt.Errorf("rule %s: level_gate.strict_tags_only=true yêu cầu required_corroboration_tags không rỗng", r.ID)
		}
	}

	if len(r.NegationFilter.TriggerWords) > 0 {
		switch r.NegationFilter.Action {
		case "downgrade_to_gate":
			if !r.LevelGate.RequireCorroboration {
				return nil, fmt.Errorf("rule %s: negation_filter.action=downgrade_to_gate yêu cầu level_gate.require_corroboration=true (negation_filter là evidence phụ cho level_gate)", r.ID)
			}
		case "suppress":
			// Không yêu cầu level_gate: suppress loại bỏ match hẳn, không cần fallback.
		default:
			return nil, fmt.Errorf("rule %s: negation_filter.action %q không được hỗ trợ (chỉ hỗ trợ \"downgrade_to_gate\" hoặc \"suppress\")", r.ID, r.NegationFilter.Action)
		}
		if r.NegationFilter.WindowChars <= 0 {
			r.NegationFilter.WindowChars = 40
		}
		for _, ref := range r.NegationFilter.AppliesToPatterns {
			if _, err := parsePatternRef(ref, len(r.Patterns)); err != nil {
				return nil, fmt.Errorf("rule %s: negation_filter.applies_to_patterns: %w", r.ID, err)
			}
		}
	}

	pe := &r.PlaceholderExclusion
	if len(pe.ValueBlocklistPatterns) > 0 {
		pe.CompiledBlocklist = make([]*regexp.Regexp, 0, len(pe.ValueBlocklistPatterns))
		for _, p := range pe.ValueBlocklistPatterns {
			compiled, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("rule %s: placeholder_exclusion.value_blocklist_patterns: bad regex %q: %w", r.ID, p, err)
			}
			pe.CompiledBlocklist = append(pe.CompiledBlocklist, compiled)
		}
	}
	if len(pe.KnownTestValues) > 0 {
		pe.NormalizedTestValues = make(map[string]struct{}, len(pe.KnownTestValues))
		for _, v := range pe.KnownTestValues {
			pe.NormalizedTestValues[string(digitsOnly([]byte(v)))] = struct{}{}
		}
	}
	if len(pe.DocContextDiscountKeywords) > 0 && (pe.DocContextDiscountFactor <= 0 || pe.DocContextDiscountFactor >= 1) {
		return nil, fmt.Errorf("rule %s: placeholder_exclusion.doc_context_discount_factor phải trong khoảng (0,1), có: %v", r.ID, pe.DocContextDiscountFactor)
	}

	if r.ProximityWindow.MaxChars > 0 {
		if !r.FPReduction.ExcludeIfNoKeywords {
			return nil, fmt.Errorf("rule %s: proximity_window yêu cầu false_positive_reduction.exclude_if_no_keywords=true", r.ID)
		}
		if r.FPReduction.MinContextWindow <= 0 {
			return nil, fmt.Errorf("rule %s: proximity_window yêu cầu false_positive_reduction.min_context_window > 0 (vế (a) trong quan hệ AND)", r.ID)
		}
		switch r.ProximityWindow.KeywordScope {
		case "":
			r.ProximityWindow.KeywordScope = "primary"
		case "primary", "primary_or_secondary":
		default:
			return nil, fmt.Errorf("rule %s: proximity_window.keyword_scope %q không hợp lệ (chỉ hỗ trợ \"primary\" hoặc \"primary_or_secondary\")", r.ID, r.ProximityWindow.KeywordScope)
		}
		switch r.ProximityWindow.FallbackOnNoBoundary {
		case "":
			r.ProximityWindow.FallbackOnNoBoundary = "window"
		case "window":
		default:
			return nil, fmt.Errorf("rule %s: proximity_window.fallback_on_no_boundary %q không hợp lệ (chỉ hỗ trợ \"window\")", r.ID, r.ProximityWindow.FallbackOnNoBoundary)
		}
	}

	for i := range r.Patterns {
		compiled, err := regexp.Compile(r.Patterns[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad regex %q: %w", r.ID, r.Patterns[i].Regex, err)
		}
		r.Patterns[i].Compiled = compiled
	}
	return &r, nil
}
