// classifier.go — Rule Engine: điều phối toàn bộ pipeline phân loại dữ liệu.
//
// # Kiến trúc "highest-sensitivity-wins"
//
// Engine hoạt động như một State Machine cấp độ file:
//
//	highest_level = PUBLIC  ← khởi tạo
//	for each rule:
//	    for each regex match:
//	        score = base_confidence × weight + context_boost
//	        if validator_fail: skip
//	        if score >= min_confidence:
//	            if match.level > highest_level:
//	                highest_level = match.level  ← ghi đè
//	after all rules:
//	    apply compound rules (có thể nâng thêm)
//	return highest_level
//
// # Fast-fail optimization
//
// Nếu FastFail=true và engine phát hiện match SECRET, scanner dừng ngay
// (không cần đọc phần còn lại của file). Tiết kiệm CPU đáng kể trong batch.
//
// # Thread safety
//
// Engine là READ-ONLY sau khi New(). Nhiều goroutine worker dùng chung một
// *Engine — không lock. Phù hợp với mô hình worker pool của scanner.
package engine

// ─── Types ────────────────────────────────────────────────────────────────────

// ClassificationLevel biểu diễn cấp độ nhạy cảm dữ liệu (4-tier framework của VNPT).
type ClassificationLevel int

const (
	Public       ClassificationLevel = 0 // Công khai — không hạn chế
	Internal     ClassificationLevel = 1 // Nội bộ — chỉ nhân viên tổ chức
	Confidential ClassificationLevel = 2 // Bảo mật — chỉ người được ủy quyền
	Secret       ClassificationLevel = 3 // Tối mật — tiếp cận cực kỳ hạn chế
)

// RuleMatch là kết quả của một lần regex pattern khớp trong nội dung file.
// Mỗi match có confidence score riêng phản ánh độ tin cậy của phát hiện.
type RuleMatch struct {
	RuleID      string             // ID rule (vd: "credit_card_001")
	RuleName    string             // Tên hiển thị (vd: "Thẻ tín dụng / ghi nợ quốc tế")
	Category    string             // Nhóm: "pii" | "financial" | "org"
	Level       ClassificationLevel // Cấp độ phân loại của match này
	Confidence  float64            // Điểm tin cậy cuối cùng: 0.0–1.0
	Offset      int64              // Vị trí byte trong file gốc (tuyệt đối)
	Length      int                // Độ dài (bytes) của đoạn khớp
	Preview     string             // Nội dung đã mask (vd: "4111****1111")
	Context     string             // Văn bản xung quanh (nội bộ; không trả raw ra ngoài)
	Value       string             // Giá trị match raw (nội bộ; phục vụ validation/forensics)
	PatternDesc string             // Mô tả pattern đã khớp (từ YAML)

	// Validated = true nếu match đã qua validator thuật toán (Luhn, CCCD prefix...).
	// Dùng làm bằng chứng "cứng" trong LevelGate corroboration — validator pass
	// gần như loại trừ khả năng false positive, khác với match chỉ dựa keyword/regex.
	Validated bool
}

// ─── Engine config ────────────────────────────────────────────────────────────

// EngineConfig chứa các tham số điều chỉnh hành vi Engine.
type EngineConfig struct {
	// MinConfidence là ngưỡng confidence tối thiểu để báo cáo một match.
	// Match có score < MinConfidence bị loại bỏ (giảm false positive).
	// Khuyến nghị: 0.60–0.75.
	MinConfidence float64

	// ContextWindow là bán kính (bytes) quanh một regex match để tìm keyword boost.
	// Lớn hơn → bắt được ngữ cảnh xa hơn; nhỏ hơn → chính xác hơn nhưng bỏ sót.
	// Khuyến nghị: 200 bytes.
	ContextWindow int

	// FastFail dừng scan ngay khi phát hiện match cấp SECRET.
	// Phù hợp khi chỉ cần biết nhãn file, không cần liệt kê toàn bộ match.
	// Tiết kiệm 40–80% CPU cho file có dữ liệu SECRET rõ ràng.
	FastFail bool

	// EntropyThreshold là ngưỡng Shannon entropy (bits/byte) để phát hiện
	// dữ liệu mã hóa hoặc secret key. Giá trị > ngưỡng → nghi ngờ SECRET.
	// Mặc định TẮT (0): entropy văn xuôi tiếng Việt UTF-8 bình thường
	// (~5.2-5.4 bits/byte) chồng lấn trực tiếp với entropy của secret thật
	// (JWT ~5.4, base64 key ~5.1) — không có ngưỡng nào tách được 2 nhóm này,
	// gây over-classify hàng loạt file tiếng Việt bình thường lên CONFIDENTIAL.
	// Chỉ bật (vd: 6.5+) nếu chắc chắn nội dung quét chủ yếu là ASCII/config.
	EntropyThreshold float64
}

// DefaultEngineConfig trả về cấu hình mặc định cân bằng giữa precision và recall.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MinConfidence:    0.60,
		ContextWindow:    200,
		FastFail:         false,
		EntropyThreshold: 0,
	}
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine là rule engine đã compile, thread-safe, dùng chung giữa các worker.
//
// Xây dựng với New() → sử dụng nhiều lần với Scan().
// Tất cả field là read-only sau khi khởi tạo → không cần mutex.
type Engine struct {
	rules    []*Rule        // Danh sách rule đã compile (regex pre-compiled)
	compound []CompoundRule // Compound rules (đọc từ YAML, không hardcode)
	kwIndex  *KeywordIndex  // Aho-Corasick index: tất cả keyword của mọi rule
	cfg      EngineConfig

	// levelGateRules là rule có level_gate.require_corroboration=true, index theo
	// RuleID. Cache lúc New() để applyLevelGate có early-return O(1) khi rỗng —
	// hot path (Scan) không trả giá cho tính năng mà đa số rule không dùng.
	levelGateRules map[string]*Rule

	// rulesByID index TOÀN BỘ rule (không chỉ rule có gate) theo RuleID —
	// dùng trong applyLevelGate để tra Tags phục vụ corroboration liên-rule
	// (xem tagCorroborationTags).
	rulesByID map[string]*Rule
}

// tagCorroborationTags: các tag mà applyLevelGate coi là 1 "họ rule" — nếu
// tổng số match (bất kể RuleID nào trong họ) mang tag này trong cùng chunk
// đạt ≥2, corroboration được thỏa cho MỌI rule có gate trong họ đó, không chỉ
// khi cùng 1 RuleID khớp ≥2 lần. Lý do: business_internal_001/hr_internal_
// business_001/healthcare_internal_business_001/business_internal_specific_001
// đều là biến thể "văn bản vận hành nội bộ chung" theo domain vocabulary
// riêng — 1 văn bản ngắn (thông báo/biên bản 1 chủ đề) thường chỉ khớp ĐÚNG
// 1 rule trong họ 1 lần (VD chỉ khớp healthcare_internal_business_001 ở
// tiêu đề "Quy chế bảo mật hồ sơ bệnh án", không có tín hiệu nào khác) —
// trước đây rơi vào PUBLIC oan vì không rule nào tự đạt ≥2 và không rule nào
// khác đạt ≥CONFIDENTIAL để corroborate (cả 4 rule này đều level INTERNAL,
// không phải "strong rule" theo nghĩa cũ). Xác nhận qua health_int_00751/
// 00768/00749/00763/00765/00784.docx (healthcare__internal, ground truth
// INTERNAL, GOT=PUBLIC trước khi sửa).
var tagCorroborationTags = map[string]bool{
	"generic_internal": true,
}

// New tạo Engine từ RuleSet đã load. Gọi một lần lúc khởi động.
// RuleSet phải đã được LoadRuleSet() xử lý (regex đã compiled).
func New(rs *RuleSet, cfg EngineConfig) *Engine {
	levelGateRules := make(map[string]*Rule)
	rulesByID := make(map[string]*Rule, len(rs.Rules))
	for _, r := range rs.Rules {
		rulesByID[r.ID] = r
		if r.LevelGate.RequireCorroboration {
			levelGateRules[r.ID] = r
		}
	}

	return &Engine{
		rules:          rs.Rules,
		compound:       rs.CompoundRules,
		kwIndex:        BuildKeywordIndex(rs),
		cfg:            cfg,
		levelGateRules: levelGateRules,
		rulesByID:      rulesByID,
	}
}

// ─── ScanOutput ───────────────────────────────────────────────────────────────

// CompoundViolation là một compound rule đã được kích hoạt với violation_type.
// Dùng để trigger workflow xử lý riêng (compliance alert, ticket, notification).
type CompoundViolation struct {
	Name          string              // Tên compound rule
	ResultLevel   ClassificationLevel // Level kết quả của rule này
	ViolationType string              // Mã vi phạm (vd: "PCI_DSS_3.3.1")
	AlertPriority string              // "CRITICAL" | "HIGH" | "MEDIUM"
}

// ScanOutput là kết quả của Engine.Scan().
type ScanOutput struct {
	// Matches là tất cả RuleMatch vượt ngưỡng confidence.
	// Được sắp xếp theo Offset (vị trí trong file).
	Matches []RuleMatch

	// FinalLevel là cấp độ phân loại cao nhất sau khi áp dụng compound rules.
	FinalLevel ClassificationLevel

	// FastFailed = true nếu scan dừng sớm do gặp match SECRET (khi FastFail=true).
	// Trong trường hợp này, Matches có thể không đầy đủ.
	FastFailed bool

	// CompoundViolations là danh sách compound rule đã trigger với violation_type.
	// Chỉ có giá trị khi compound rule có trường violation_type != "".
	// Dùng để audit log và phân loại vi phạm theo chuẩn (PCI-DSS, HIPAA, ...).
	CompoundViolations []CompoundViolation
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

// Scan chạy toàn bộ classification pipeline trên một chunk nội dung.
//
// baseOffset là vị trí byte của chunk trong file gốc.
// Với file nhỏ (< 1MB), baseOffset = 0 và chunk = toàn bộ nội dung.
// Với file lớn, scanner cắt file thành chunks và gọi Scan nhiều lần.
//
// Thread-safe: nhiều goroutine có thể gọi Scan đồng thời trên cùng *Engine.
func (e *Engine) Scan(chunk []byte, baseOffset int64) ScanOutput {
	if len(chunk) == 0 {
		return ScanOutput{FinalLevel: Public}
	}

	// ── Step 1: Aho-Corasick keyword pre-scan ──────────────────────────────
	// O(n + m) — tìm tất cả keyword xuất hiện trong chunk.
	// Kết quả (HitMap) dùng cho:
	//   a) Quyết định có chạy regex cho rule không (bộ lọc)
	//   b) Tính context boost sau khi regex match
	hits := e.kwIndex.Scan(chunk)

	opts := matchOpts{
		minConfidence: e.cfg.MinConfidence,
		contextWindow: e.cfg.ContextWindow,
	}

	var allMatches []RuleMatch
	finalLevel := Public
	fastFailed := false

	// ── Step 2: Per-rule regex matching + confidence scoring ───────────────
	for _, rule := range e.rules {
		// Tối ưu: bỏ qua rule nếu tất cả pattern đều context_required
		// mà không có keyword nào cho rule này trong chunk.
		if !hits.HasRule(rule.ID) && allPatternsContextRequired(rule) {
			continue
		}

		// Enforce min_secondary: bỏ qua rule nếu số secondary keyword < ngưỡng.
		// Ngăn income rule khớp budget docs chỉ có "lương" mà thiếu BHXH/phiếu lương.
		if rule.KeywordLogic.MinSecondary > 0 {
			secCount := 0
			for _, hit := range hits[rule.ID] {
				if !hit.Primary {
					secCount++
					if secCount >= rule.KeywordLogic.MinSecondary {
						break
					}
				}
			}
			if secCount < rule.KeywordLogic.MinSecondary {
				continue
			}
		}

		ruleMatches := matchAllPatterns(chunk, rule, hits, baseOffset, opts)
		if len(ruleMatches) == 0 {
			continue
		}

		allMatches = append(allMatches, ruleMatches...)

		// ── Step 3 (inline): Highest-sensitivity-wins ─────────────────────
		// Cập nhật finalLevel sau mỗi rule để cho phép fast-fail.
		for _, m := range ruleMatches {
			if m.Level > finalLevel {
				finalLevel = m.Level
			}
		}

		// ── Step 4: Fast-fail ─────────────────────────────────────────────
		// Nếu đã đạt mức cao nhất có thể (SECRET), không cần scan thêm.
		if e.cfg.FastFail && finalLevel == Secret {
			fastFailed = true
			break
		}
	}

	// ── Step 4.5: Level gate ───────────────────────────────────────────────
	// Hạ level của match thuộc rule level_gate.require_corroboration=true mà
	// không có bằng chứng thứ 2 (validator, ≥2 lần khớp, hoặc rule khác cùng
	// xuất hiện ở level ≥ CONFIDENTIAL). Ngược lại Step 3: có thể HẠ finalLevel,
	// không chỉ nâng — chống 1 match SECRET đơn lẻ, không kiểm chứng được, quyết
	// định nhãn nghiêm trọng nhất cho cả file (xem rules.go: LevelGate).
	//
	// Bỏ qua khi fastFailed=true: scan đã dừng sớm, allMatches không đầy đủ nên
	// không đủ dữ liệu để đánh giá corroboration đáng tin cậy.
	if !fastFailed && len(e.levelGateRules) > 0 && len(allMatches) > 0 {
		finalLevel = e.applyLevelGate(allMatches)
	}

	// ── Step 5: Entropy check ─────────────────────────────────────────────
	// Phát hiện dữ liệu mã hóa / secret key không có pattern rõ ràng.
	// Ví dụ: private key, encrypted blob, random token.
	if !fastFailed && e.cfg.EntropyThreshold > 0 && finalLevel < Secret && len(allMatches) > 0 && len(chunk) >= 1024 {
		if IsHighEntropy(chunk, e.cfg.EntropyThreshold) {
			// Nâng lên CONFIDENTIAL nếu entropy cao nhưng chưa có match nào.
			// Không tạo thêm RuleMatch vì không có rule ID cụ thể.
			if finalLevel < Confidential {
				finalLevel = Confidential
			}
		}
	}

	// ── Step 6: Compound rules ────────────────────────────────────────────
	// Đọc từ YAML compound_rules — không hardcode trong Go code.
	// Ví dụ: [pii + financial] → SECRET; [org + pii] → CONFIDENTIAL
	var compoundViolations []CompoundViolation
	if !fastFailed && len(allMatches) > 0 {
		finalLevel, compoundViolations = e.applyCompoundRules(allMatches, finalLevel)
	}

	return ScanOutput{
		Matches:            allMatches,
		FinalLevel:         finalLevel,
		FastFailed:         fastFailed,
		CompoundViolations: compoundViolations,
	}
}

// ─── Volume escalation ─────────────────────────────────────────────────────────

// VolumeEscalationEvent ghi lại một lần volume escalation đã kích hoạt.
// Dùng cho audit log — giải thích tại sao FinalLevel bị nâng dù từng match
// riêng lẻ có level thấp hơn.
type VolumeEscalationEvent struct {
	RuleID      string
	Count       int
	ResultLevel ClassificationLevel
}

// ApplyVolumeEscalation nâng ClassificationLevel dựa trên SỐ LẦN mỗi rule khớp
// trong toàn bộ file (không phải một chunk — xem ghi chú ở scanner.ScanFile).
//
// Đây là bước tách biệt khỏi Confidence scoring: confidence của một match phản
// ánh "match này có phải PII/secret thật không", không đổi theo số lượng match
// khác. Volume escalation phản ánh một câu hỏi khác — "mức độ rủi ro lộ lọt của
// CẢ FILE" — 500 email trong 1 file là sự cố nghiêm trọng hơn 1 email lẻ dù mỗi
// match confidence như nhau. Vì vậy cơ chế này chỉ nâng ClassificationLevel,
// không chỉnh sửa Confidence của match đã có (giữ nguyên ý nghĩa của điểm số).
//
// counts là số match đã qua minConfidence của mỗi ruleID trong TOÀN FILE
// (caller — scanner — chịu trách nhiệm gộp qua các chunk và dedup).
//
// Nguyên tắc No-Downgrade giống compound rules: chỉ nâng level, không hạ.
func (e *Engine) ApplyVolumeEscalation(counts map[string]int, current ClassificationLevel) (ClassificationLevel, []VolumeEscalationEvent) {
	maxLevel := current
	var events []VolumeEscalationEvent

	for _, rule := range e.rules {
		thresholds := rule.VolumeEscalation.Thresholds
		if len(thresholds) == 0 {
			continue
		}
		count := counts[rule.ID]
		if count == 0 {
			continue
		}

		// Thresholds đã sort tăng dần theo MinCount lúc load (xem loadRule).
		// Duyệt từ cao xuống thấp để lấy bậc cao nhất mà count đạt được.
		for i := len(thresholds) - 1; i >= 0; i-- {
			t := thresholds[i]
			if count < t.MinCount {
				continue
			}
			if t.ParsedLevel > maxLevel {
				maxLevel = t.ParsedLevel
			}
			events = append(events, VolumeEscalationEvent{
				RuleID:      rule.ID,
				Count:       count,
				ResultLevel: t.ParsedLevel,
			})
			break
		}
	}

	return maxLevel, events
}

// ─── Level gate ─────────────────────────────────────────────────────────────────

// applyLevelGate hạ Level của các RuleMatch thuộc rule có level_gate bật mà
// thiếu corroboration, rồi trả về finalLevel tính lại (max trên toàn bộ
// allMatches SAU khi đã hạ). Mutate trực tiếp Level trong allMatches để kết
// quả trả ra ngoài (Matches, và compound rules chạy sau) nhất quán với
// finalLevel — người dùng không thấy match "SECRET" trong danh sách trong khi
// FinalLevel của file lại là CONFIDENTIAL.
//
// Phạm vi: chỉ trong 1 chunk (giống compound rules) — xem giới hạn tương tự ở
// ApplyVolumeEscalation. Corroboration bằng "rule khác cùng chunk" vì vậy có
// thể bỏ sót trường hợp 2 rule hỗ trợ nhau nằm ở 2 chunk khác nhau của cùng
// file lớn; chấp nhận được vì mục tiêu là chống FP (thiên về thận trọng hơn),
// không phải tối đa hóa recall.
func (e *Engine) applyLevelGate(matches []RuleMatch) ClassificationLevel {
	counts := make(map[string]int, len(matches))
	validatedByRule := make(map[string]bool, len(matches))
	strongRuleIDs := make(map[string]bool, len(matches))
	tagCounts := make(map[string]int, 4)
	for _, m := range matches {
		counts[m.RuleID]++
		if m.Validated {
			validatedByRule[m.RuleID] = true
		}
		if m.Level >= Confidential {
			strongRuleIDs[m.RuleID] = true
		}
		if r := e.rulesByID[m.RuleID]; r != nil {
			for _, tag := range r.Tags {
				if tagCorroborationTags[tag] {
					tagCounts[tag]++
				}
			}
		}
	}
	hasOtherStrongRule := func(ruleID string) bool {
		for id := range strongRuleIDs {
			if id != ruleID {
				return true
			}
		}
		return false
	}
	// hasFamilyCorroboration: ≥2 match (bất kể RuleID) cùng mang 1 tag trong
	// tagCorroborationTags — xem giải thích ở khai báo tagCorroborationTags.
	hasFamilyCorroboration := func(ruleID string) bool {
		r := e.rulesByID[ruleID]
		if r == nil {
			return false
		}
		for _, tag := range r.Tags {
			if tagCorroborationTags[tag] && tagCounts[tag] >= 2 {
				return true
			}
		}
		return false
	}

	finalLevel := Public
	for i := range matches {
		m := &matches[i]
		rule, gated := e.levelGateRules[m.RuleID]
		if gated {
			corroborated := validatedByRule[m.RuleID] ||
				counts[m.RuleID] >= 2 ||
				hasOtherStrongRule(m.RuleID) ||
				hasFamilyCorroboration(m.RuleID)
			if !corroborated && m.Level > rule.LevelGate.ParsedFallbackLevel {
				m.Level = rule.LevelGate.ParsedFallbackLevel
			}
		}
		if m.Level > finalLevel {
			finalLevel = m.Level
		}
	}
	return finalLevel
}

// ─── Compound rules ───────────────────────────────────────────────────────────

// applyCompoundRules đánh giá tất cả compound rules và trả về level cao nhất
// cùng danh sách violation đã kích hoạt (chỉ những rule có violation_type).
//
// Compound rule kích hoạt khi TẤT CẢ điều kiện trong conditions đều được thỏa mãn.
// Mỗi điều kiện được so sánh với:
//   - Category của match (vd: "pii", "financial")
//   - Rule ID prefix (vd: "vn_id" từ rule "vn_id_001")
//   - Tổ hợp category_prefix (vd: "pii_vn_id")
//   - Rule ID đầy đủ (vd: "classified_doc_001")
//
// Nguyên tắc No-Downgrade được đảm bảo ngầm: engine chỉ cập nhật maxLevel
// khi cr.ResultLevel > maxLevel; compound không bao giờ giảm cấp đã đạt.
//
// Ví dụ từ rules.yaml:
//
//	conditions: [pii, financial], min_component_level: CONFIDENTIAL
//	  → chỉ thỏa khi có match pii ≥ L3 VÀ financial ≥ L3 (tránh email+BIC → SECRET)
//	conditions: [pii_vn_id, pii_phone, pii_dob]
//	  → thỏa khi có đủ 3 loại PII cụ thể
func (e *Engine) applyCompoundRules(matches []RuleMatch, current ClassificationLevel) (ClassificationLevel, []CompoundViolation) {
	if len(e.compound) == 0 {
		return current, nil
	}

	tags := buildTagSet(matches)
	tagLevels := buildTagLevelMap(matches)

	maxLevel := current
	var violations []CompoundViolation

	for _, cr := range e.compound {
		// Bỏ qua nếu rule không tăng level VÀ không có violation_type để ghi nhận.
		// Tối ưu hot path: tránh evaluate conditions không cần thiết.
		if cr.ResultLevel <= maxLevel && cr.ViolationType == "" {
			continue
		}
		if !compoundSatisfied(cr.Conditions, tags) {
			continue
		}
		// min_component_level: MỖI condition phải có match ở level >= ngưỡng.
		// Tránh false positive: email(INTERNAL) + BIC(INTERNAL) không trigger SECRET.
		if cr.MinComponentLevel > 0 && !compoundMinLevelSatisfied(cr.Conditions, tagLevels, cr.MinComponentLevel) {
			continue
		}
		// context_conditions: tag phải CÓ MẶT (bất kể level) — dùng để thu hẹp
		// phạm vi domain mà không đòi hỏi cùng ngưỡng MinComponentLevel cao như
		// Conditions (xem giải thích ở CompoundRule.ContextConditions).
		if len(cr.ContextConditions) > 0 && !compoundSatisfied(cr.ContextConditions, tags) {
			continue
		}

		if cr.ResultLevel > maxLevel {
			maxLevel = cr.ResultLevel
		}
		if cr.ViolationType != "" {
			violations = append(violations, CompoundViolation{
				Name:          cr.Name,
				ResultLevel:   cr.ResultLevel,
				ViolationType: cr.ViolationType,
				AlertPriority: cr.AlertPriority,
			})
		}
	}
	return maxLevel, violations
}

// buildTagLevelMap maps mỗi tag đến level cao nhất của match tương ứng.
// Dùng để kiểm tra min_component_level constraint trong compound rules.
func buildTagLevelMap(matches []RuleMatch) map[string]ClassificationLevel {
	m := make(map[string]ClassificationLevel, len(matches)*4)
	for _, match := range matches {
		prefix := ruleIDPrefix(match.RuleID)
		catPrefix := match.Category + "_" + prefix
		for _, tag := range [4]string{match.Category, match.RuleID, prefix, catPrefix} {
			if match.Level > m[tag] {
				m[tag] = match.Level
			}
		}
	}
	return m
}

// compoundMinLevelSatisfied trả về true nếu MỌI condition có ít nhất một match
// ở level >= minLevel. Đây là điều kiện cần thêm bên cạnh compoundSatisfied.
func compoundMinLevelSatisfied(conditions []string, tagLevels map[string]ClassificationLevel, minLevel ClassificationLevel) bool {
	for _, cond := range conditions {
		if tagLevels[cond] < minLevel {
			return false
		}
	}
	return true
}

// buildTagSet xây dựng tập hợp tag từ danh sách match và rule definition.
// Tag bao gồm: category, ruleID, ruleID prefix, category_prefix, custom Tags từ YAML.
func buildTagSet(matches []RuleMatch) map[string]bool {
	tags := make(map[string]bool, len(matches)*4)
	for _, m := range matches {
		tags[m.Category] = true          // vd: "pii"
		tags[m.RuleID] = true            // vd: "vn_id_001"
		prefix := ruleIDPrefix(m.RuleID) // vd: "vn_id"
		tags[prefix] = true
		tags[m.Category+"_"+prefix] = true // vd: "pii_vn_id"
	}
	return tags
}

// addRuleTagsToSet thêm Tags tùy chỉnh từ Rule YAML vào tagSet.
// Gọi từ Engine khi cần phân tích compound rules chi tiết hơn.
func addRuleTagsToSet(rule *Rule, tags map[string]bool) {
	for _, t := range rule.Tags {
		tags[t] = true
	}
}

// compoundSatisfied kiểm tra tất cả conditions đều có trong tagSet.
func compoundSatisfied(conditions []string, tags map[string]bool) bool {
	for _, cond := range conditions {
		if !tags[cond] {
			return false
		}
	}
	return true
}

// ruleIDPrefix trích xuất prefix có nghĩa từ rule ID.
// Quy ước: rule ID kết thúc bằng _NNN (số thứ tự).
//
//	"vn_id_001"      → "vn_id"
//	"credit_card_001" → "credit_card"
//	"email_001"       → "email"
func ruleIDPrefix(id string) string {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] != '_' {
			continue
		}
		suffix := id[i+1:]
		if len(suffix) == 0 {
			continue
		}
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return id[:i]
		}
	}
	return id
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// allPatternsContextRequired kiểm tra xem tất cả pattern của rule có đều
// yêu cầu context keyword không. Dùng để tối ưu: bỏ qua rule khi không có keyword.
func allPatternsContextRequired(rule *Rule) bool {
	if len(rule.Patterns) == 0 {
		return false
	}
	for _, pat := range rule.Patterns {
		if !pat.ContextRequired {
			return false
		}
	}
	return true
}

// ─── Backward compatibility ───────────────────────────────────────────────────

// Classify là hàm tương thích ngược với code cũ.
// Với code mới, hãy dùng Engine.Scan() để có đầy đủ pipeline.
//
// Deprecated: Use Engine.Scan() instead.
func Classify(matches []RuleMatch, _ float64) ClassificationLevel {
	level := Public
	for _, m := range matches {
		if m.Level > level {
			level = m.Level
		}
	}
	return level
}
