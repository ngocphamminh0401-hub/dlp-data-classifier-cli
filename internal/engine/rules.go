// Package engine — rule loading and compilation from YAML rule files.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	Compiled        *regexp.Regexp
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
//
// Không đủ corroboration → level của match bị hạ về FallbackLevel.
//
// Rule KHÔNG nên bật cờ này nếu 1 match đơn lẻ ĐÃ LÀ rủi ro thật dù không lặp lại
// (vd: credentials_001 — một API key thật rò rỉ 1 lần vẫn là sự cố nghiêm trọng).
type LevelGate struct {
	RequireCorroboration bool   `yaml:"require_corroboration"`
	FallbackLevel        string `yaml:"fallback_level"`
	ParsedFallbackLevel  ClassificationLevel
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
}

// RuleSet is the full set of loaded and compiled rules.
type RuleSet struct {
	Rules         []*Rule
	CompoundRules []CompoundRule
}

type masterIndex struct {
	Includes []string `yaml:"includes"`
	Compound []struct {
		Name              string   `yaml:"name"`
		Conditions        []string `yaml:"conditions"`
		ContextConditions []string `yaml:"context_conditions"`
		ResultLevel       string   `yaml:"result_level"`
		MinComponentLevel string   `yaml:"min_component_level"`
		ViolationType     string   `yaml:"violation_type"`
		AlertPriority     string   `yaml:"alert_priority"`
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
		rs.CompoundRules = append(rs.CompoundRules, CompoundRule{
			Name:              cr.Name,
			Conditions:        cr.Conditions,
			ContextConditions: cr.ContextConditions,
			ResultLevel:       ParseLevel(cr.ResultLevel),
			MinComponentLevel: ParseLevel(cr.MinComponentLevel),
			ViolationType:     cr.ViolationType,
			AlertPriority:     cr.AlertPriority,
		})
	}

	// Sắp xếp rules theo Priority giảm dần: rule quan trọng (credit card,
	// secret key) được đánh giá trước → fast-fail kích hoạt sớm hơn.
	sort.SliceStable(rs.Rules, func(i, j int) bool {
		return rs.Rules[i].Priority > rs.Rules[j].Priority
	})

	return rs, nil
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
