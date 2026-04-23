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

	for i := range r.Patterns {
		compiled, err := regexp.Compile(r.Patterns[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad regex %q: %w", r.ID, r.Patterns[i].Regex, err)
		}
		r.Patterns[i].Compiled = compiled
	}
	return &r, nil
}
