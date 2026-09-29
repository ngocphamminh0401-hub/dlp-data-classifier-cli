package engine

import (
	"path/filepath"
	"regexp"
	"testing"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func compileTestRule(r *Rule) *Rule {
	for i := range r.Patterns {
		r.Patterns[i].Compiled = regexp.MustCompile(r.Patterns[i].Regex)
	}
	if r.Weight == 0 {
		r.Weight = 1
	}
	if r.Level != "" {
		r.ParsedLevel = ParseLevel(r.Level)
	}
	if r.LevelGate.RequireCorroboration {
		r.LevelGate.ParsedFallbackLevel = ParseLevel(r.LevelGate.FallbackLevel)
	}
	return r
}

func newTestEngine(rules ...*Rule) *Engine {
	return New(&RuleSet{Rules: rules}, EngineConfig{MinConfidence: 0.05, ContextWindow: 200})
}

// ─── Per-counter tests ────────────────────────────────────────────────────────

func TestTelemetry_ContextRequiredSkip_InMatchAllPatterns(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_ctx", Category: "pii", Level: "CONFIDENTIAL",
		Patterns: []RulePattern{
			{Regex: `\d{6}`, Confidence: 0.9, ContextRequired: true},
			{Regex: `zzzznomatch`, Confidence: 0.9}, // non-context => không bị skip ở classifier
		},
		Keywords: RuleKeywords{Primary: []string{"sohoso"}},
	})
	out := newTestEngine(r).Scan([]byte("gia tri 123456 xuat hien"), 0)

	if out.Telemetry.ContextRequiredSkipCount != 1 {
		t.Fatalf("ContextRequiredSkipCount = %d, want 1", out.Telemetry.ContextRequiredSkipCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_ContextRequiredSkip_ClassifierShortcutNotCounted(t *testing.T) {
	// Rule KHÔNG có keyword nào trong chunk + tất cả pattern context_required
	// → bị bỏ qua ở classifier.go TRƯỚC matchAllPatterns → CỐ Ý không đếm
	// (rule không liên quan file, không phải near-miss).
	r := compileTestRule(&Rule{
		ID: "t_ctx2", Category: "pii", Level: "CONFIDENTIAL",
		Patterns: []RulePattern{
			{Regex: `\d{6}`, Confidence: 0.9, ContextRequired: true},
			{Regex: `\d{7}`, Confidence: 0.9, ContextRequired: true},
		},
		Keywords: RuleKeywords{Primary: []string{"khoa"}},
	})
	out := newTestEngine(r).Scan([]byte("value 123456 and 1234567"), 0)

	if out.Telemetry.ContextRequiredSkipCount != 0 {
		t.Fatalf("ContextRequiredSkipCount = %d, want 0 (shortcut không đếm)", out.Telemetry.ContextRequiredSkipCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_ValidatorFail(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_val", Category: "financial", Level: "CONFIDENTIAL",
		Patterns: []RulePattern{{Regex: `\d{16}`, Confidence: 0.9, Validators: []string{"luhn"}}},
	})
	// 4111111111111111 hợp lệ Luhn; ...112 sai 1 đơn vị → fail.
	out := newTestEngine(r).Scan([]byte("card 4111111111111112 here"), 0)

	if out.Telemetry.ValidatorFailCount != 1 {
		t.Fatalf("ValidatorFailCount = %d, want 1", out.Telemetry.ValidatorFailCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_ProximityReject(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_prox", Category: "pii", Level: "CONFIDENTIAL",
		Patterns:    []RulePattern{{Regex: `\d{9}`, Confidence: 0.9}},
		Keywords:    RuleKeywords{Primary: []string{"tai khoan"}},
		FPReduction: FPReduction{ExcludeIfNoKeywords: true, MinContextWindow: 30},
		ProximityWindow: ProximityWindow{
			MaxChars: 20, KeywordScope: "primary", FallbackOnNoBoundary: "window",
		},
	})
	out := newTestEngine(r).Scan([]byte("so 123456789 khong co nhan gi ca"), 0)

	if out.Telemetry.ProximityRejectCount != 1 {
		t.Fatalf("ProximityRejectCount = %d, want 1", out.Telemetry.ProximityRejectCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_NegationSuppress(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_negsup", Category: "org", Level: "SECRET",
		Patterns:       []RulePattern{{Regex: `SECRET-\d+`, Confidence: 0.95}},
		NegationFilter: NegationFilter{TriggerWords: []string{"khong phai"}, Action: "suppress", WindowChars: 40},
	})
	out := newTestEngine(r).Scan([]byte("day khong phai la SECRET-123 that"), 0)

	if out.Telemetry.NegationSuppressCount != 1 {
		t.Fatalf("NegationSuppressCount = %d, want 1", out.Telemetry.NegationSuppressCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_NegationDowngrade(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_negdown", Category: "org", Level: "SECRET",
		Patterns:       []RulePattern{{Regex: `SECRET-\d+`, Confidence: 0.95}},
		NegationFilter: NegationFilter{TriggerWords: []string{"khong phai"}, Action: "downgrade_to_gate", WindowChars: 40},
		LevelGate:      LevelGate{RequireCorroboration: true, FallbackLevel: "INTERNAL"},
	})
	out := newTestEngine(r).Scan([]byte("day khong phai SECRET-123"), 0)

	if out.Telemetry.NegationDowngradeCount != 1 {
		t.Fatalf("NegationDowngradeCount = %d, want 1", out.Telemetry.NegationDowngradeCount)
	}
	if out.Telemetry.LevelGateDowngradeCount != 0 {
		t.Fatalf("LevelGateDowngradeCount = %d, want 0 (đã ở mức fallback)", out.Telemetry.LevelGateDowngradeCount)
	}
	if out.FinalLevel != Internal {
		t.Fatalf("FinalLevel = %v, want Internal", out.FinalLevel)
	}
}

func TestTelemetry_LevelGateDowngrade(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_gate", Category: "org", Level: "SECRET",
		Patterns:  []RulePattern{{Regex: `TOPSECRET`, Confidence: 0.95}},
		LevelGate: LevelGate{RequireCorroboration: true, FallbackLevel: "PUBLIC"},
	})
	out := newTestEngine(r).Scan([]byte("this doc is TOPSECRET"), 0)

	if out.Telemetry.LevelGateDowngradeCount != 1 {
		t.Fatalf("LevelGateDowngradeCount = %d, want 1", out.Telemetry.LevelGateDowngradeCount)
	}
	if out.FinalLevel != Public {
		t.Fatalf("FinalLevel = %v, want Public", out.FinalLevel)
	}
}

func TestTelemetry_KeywordHitNoMatch(t *testing.T) {
	r := compileTestRule(&Rule{
		ID: "t_kwnm", Category: "pii", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `WONTMATCHZZZ`, Confidence: 0.9}},
		Keywords: RuleKeywords{Primary: []string{"han muc"}},
	})
	out := newTestEngine(r).Scan([]byte("han muc tin dung cua khach"), 0)

	if got := out.Telemetry.KeywordHitNoMatchRules["t_kwnm"]; got != 1 {
		t.Fatalf("KeywordHitNoMatchRules[t_kwnm] = %d, want 1", got)
	}
	if out.Telemetry.KeywordHitNoMatchPrimaryRuleCount != 1 {
		t.Fatalf("KeywordHitNoMatchPrimaryRuleCount = %d, want 1 (primary keyword hit, no match)", out.Telemetry.KeywordHitNoMatchPrimaryRuleCount)
	}
	if len(out.Matches) != 0 || out.FinalLevel != Public {
		t.Fatalf("classification changed: matches=%d level=%v", len(out.Matches), out.FinalLevel)
	}
}

func TestTelemetry_KeywordHitNoMatchPrimary_SecondaryOnlyNotCounted(t *testing.T) {
	// Keyword SECONDARY hit + rule không match → keyword_hit_no_match_total tăng
	// nhưng KeywordHitNoMatchPrimaryRuleCount KHÔNG (chỉ đếm primary).
	r := compileTestRule(&Rule{
		ID: "t_kwsec", Category: "pii", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `WONTMATCHZZZ`, Confidence: 0.9}},
		Keywords: RuleKeywords{Primary: []string{"nonexistentprimary"}, Secondary: []string{"tham chieu"}},
	})
	out := newTestEngine(r).Scan([]byte("tai lieu co tham chieu noi bo"), 0)

	if out.Telemetry.KeywordHitNoMatchRules["t_kwsec"] == 0 {
		t.Fatalf("expected secondary keyword hit recorded in KeywordHitNoMatchRules")
	}
	if out.Telemetry.KeywordHitNoMatchPrimaryRuleCount != 0 {
		t.Fatalf("KeywordHitNoMatchPrimaryRuleCount = %d, want 0 (secondary-only)", out.Telemetry.KeywordHitNoMatchPrimaryRuleCount)
	}
}

func TestTelemetry_UnstructuredNumericHits(t *testing.T) {
	r := compileTestRule(&Rule{ID: "t_noop", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `WONTMATCH`, Confidence: 0.9}}})
	out := newTestEngine(r).Scan([]byte("ref 123456789012 and 87654321 end 42"), 0)

	if out.Telemetry.UnstructuredNumericHits != 2 {
		t.Fatalf("UnstructuredNumericHits = %d, want 2", out.Telemetry.UnstructuredNumericHits)
	}
}

func TestTelemetry_UnstructuredNumericHits_SkipsMatched(t *testing.T) {
	// Dãy 16 số khớp rule → KHÔNG tính là unstructured; dãy 8 số còn lại thì có.
	r := compileTestRule(&Rule{ID: "t_num", Category: "financial", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `\d{16}`, Confidence: 0.9}}})
	out := newTestEngine(r).Scan([]byte("a 4111111111111111 b 12345678 c"), 0)

	if len(out.Matches) != 1 {
		t.Fatalf("want 1 match for the 16-digit run, got %d", len(out.Matches))
	}
	if out.Telemetry.UnstructuredNumericHits != 1 {
		t.Fatalf("UnstructuredNumericHits = %d, want 1", out.Telemetry.UnstructuredNumericHits)
	}
}

func TestTelemetry_DocContextDiscountAndChunkStats(t *testing.T) {
	r := compileTestRule(&Rule{ID: "t_noop2", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `WONTMATCH`, Confidence: 0.9}}})
	chunk := []byte("day la vi du minh hoa cho tai lieu")
	out := newTestEngine(r).Scan(chunk, 0)

	if out.Telemetry.DocContextDiscountCount != 1 {
		t.Fatalf("DocContextDiscountCount = %d, want 1", out.Telemetry.DocContextDiscountCount)
	}
	if out.Telemetry.ChunkCount != 1 {
		t.Fatalf("ChunkCount = %d, want 1", out.Telemetry.ChunkCount)
	}
	if out.Telemetry.TotalBytes != int64(len(chunk)) {
		t.Fatalf("TotalBytes = %d, want %d", out.Telemetry.TotalBytes, len(chunk))
	}
}

func TestTelemetry_EmptyChunkNoPanic(t *testing.T) {
	r := compileTestRule(&Rule{ID: "t_noop3", Level: "INTERNAL",
		Patterns: []RulePattern{{Regex: `x`, Confidence: 0.9}}})
	out := newTestEngine(r).Scan(nil, 0)
	if out.FinalLevel != Public || out.Telemetry.ChunkCount != 0 {
		t.Fatalf("empty chunk: level=%v chunkCount=%d", out.FinalLevel, out.Telemetry.ChunkCount)
	}
}

func TestFileScanTelemetryMerge(t *testing.T) {
	a := FileScanTelemetry{
		ContextRequiredSkipCount: 1, ValidatorFailCount: 2, ProximityRejectCount: 3,
		NegationSuppressCount: 1, NegationDowngradeCount: 1, LevelGateDowngradeCount: 4,
		ChunkCount: 1, ChunkErrorCount: 1, TotalBytes: 100, UnstructuredNumericHits: 5,
		DocContextDiscountCount: 1,
		KeywordHitNoMatchRules:  map[string]int{"r1": 2},
	}
	a.Merge(FileScanTelemetry{
		ValidatorFailCount: 1, ChunkCount: 1, TotalBytes: 50,
		KeywordHitNoMatchRules: map[string]int{"r1": 1, "r2": 3},
	})
	if a.ValidatorFailCount != 3 || a.ChunkCount != 2 || a.TotalBytes != 150 {
		t.Fatalf("merge scalars wrong: %+v", a)
	}
	if a.KeywordHitNoMatchRules["r1"] != 3 || a.KeywordHitNoMatchRules["r2"] != 3 {
		t.Fatalf("merge map wrong: %v", a.KeywordHitNoMatchRules)
	}
	if got := (FileScanTelemetry{ChunkCount: 3, ChunkErrorCount: 1}).ChunkErrorRatio(); got != 0.25 {
		t.Fatalf("ChunkErrorRatio = %v, want 0.25", got)
	}
}

// ─── Regression: classification không đổi khi có instrumentation ──────────────
//
// Golden snapshot của FinalLevel trên tập input mẫu, chạy với ruleset thật
// (commit khóa 4c697c7). Bất kỳ thay đổi nào ở đây nghĩa là instrumentation đã
// vô tình chạm vào logic phân loại — vi phạm bất biến Pha 1.
func TestTelemetryClassificationUnchanged(t *testing.T) {
	eng, err := CompileFromDir(filepath.Join("..", "..", "rules"), DefaultEngineConfig())
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  ClassificationLevel
	}{
		{"empty", "", Public},
		{"plain", "Xin chao, day la email trao doi cong viec binh thuong khong nhay cam.", Public},
		{"otp", "Ma OTP giao dich cua quy khach la 847213. Khong chia se ma nay cho bat ky ai.", Secret},
		// Golden = hành vi hiện tại của ruleset khóa (4c697c7), KHÔNG phải kỳ
		// vọng lý thuyết — mục đích test là phát hiện drift, không đánh giá rule.
		{"credit_card", "Thong tin the: 4111 1111 1111 1111, CVV: 123, ngay het han 12/26. Chu the Nguyen Van A.", Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := eng.Scan([]byte(tc.input), 0)
			if out.FinalLevel != tc.want {
				t.Fatalf("FinalLevel = %v, want %v (golden snapshot — instrumentation không được đổi kết quả)", out.FinalLevel, tc.want)
			}
		})
	}
}
