// aho_corasick.go — Keyword index dùng thuật toán Aho-Corasick.
//
// # Vai trò trong pipeline
//
// KeywordIndex là bộ lọc CẤP ĐỘ ĐẦU TIÊN trước khi chạy Regex.
// Mục tiêu: loại bỏ sớm các chunk/file không chứa dấu hiệu nhạy cảm,
// tránh lãng phí CPU vào Regex engine cho nội dung "sạch".
//
// # Tại sao Aho-Corasick?
//
//   - Độ phức tạp: O(n + m) — n là kích thước chunk, m là tổng số keyword.
//     Khác với naive scan: O(n × k) với k là số keyword.
//   - 107 keyword của 9 rule hiện tại → Aho-Corasick scan cực nhanh.
//   - Kết quả trả về ngay vị trí match → dùng luôn cho proximity scoring.
//
// # Thread safety
//
// KeywordIndex là READ-ONLY sau khi Build. Nhiều goroutine worker
// dùng chung một pointer trỏ về Engine.kwIndex — không cần lock.
package engine

import (
	"bytes"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// ─── KeywordIndex ─────────────────────────────────────────────────────────────

// kwEntry ánh xạ một keyword lowercased sang rule chứa nó.
type kwEntry struct {
	ruleID  string
	primary bool // primary keyword → boost cao hơn secondary
}

// KeywordIndex là trie Aho-Corasick đã compile, chứa tất cả keyword từ mọi rule.
// Xây dựng một lần lúc khởi động qua BuildKeywordIndex(); sau đó read-only.
type KeywordIndex struct {
	trie  *ahocorasick.Trie    // nil nếu không có keyword nào
	kwMap map[string][]kwEntry // lowercase keyword → các rule chứa keyword này
}

// ─── HitMap ───────────────────────────────────────────────────────────────────

// KeywordHit ghi lại một lần keyword xuất hiện trong chunk.
type KeywordHit struct {
	Keyword string // keyword đã khớp (lowercase)
	Offset  int64  // vị trí byte trong chunk
	Primary bool   // true nếu là primary keyword (boost cao hơn)
}

// HitMap nhóm các KeywordHit theo rule ID.
// Key = rule.ID, Value = danh sách hit trong chunk.
type HitMap map[string][]KeywordHit

// HasRule báo cáo chunk có chứa ít nhất một keyword của ruleID không.
func (h HitMap) HasRule(ruleID string) bool {
	return len(h[ruleID]) > 0
}

// PrimaryCount trả về số primary keyword hits của ruleID trong chunk.
func (h HitMap) PrimaryCount(ruleID string) int {
	n := 0
	for _, hit := range h[ruleID] {
		if hit.Primary {
			n++
		}
	}
	return n
}

// NearMatch kiểm tra xem có keyword nào của ruleID nằm trong phạm vi window
// byte quanh vị trí [matchStart, matchEnd) không.
// Dùng để quyết định context boost cho một regex match cụ thể.
func (h HitMap) NearMatch(ruleID string, matchStart, matchEnd int64, window int) (hasPrimary, hasSecondary bool) {
	for _, hit := range h[ruleID] {
		dist := kwDistance(hit.Offset, matchStart, matchEnd)
		if dist > int64(window) {
			continue
		}
		if hit.Primary {
			hasPrimary = true
		} else {
			hasSecondary = true
		}
		if hasPrimary && hasSecondary {
			break // đã có đủ thông tin, thoát sớm
		}
	}
	return hasPrimary, hasSecondary
}

// kwDistance tính khoảng cách (bytes) giữa keyword tại kwOffset và match [start, end).
// Trả về 0 nếu keyword nằm trong match.
func kwDistance(kwOffset, matchStart, matchEnd int64) int64 {
	if kwOffset >= matchStart && kwOffset < matchEnd {
		return 0
	}
	if kwOffset < matchStart {
		return matchStart - kwOffset
	}
	return kwOffset - matchEnd + 1
}

// ─── Build ────────────────────────────────────────────────────────────────────

// BuildKeywordIndex tạo KeywordIndex từ tất cả rule trong RuleSet.
// Gọi một lần lúc khởi động. Kết quả là read-only, an toàn cho concurrent use.
//
// Các nguồn keyword được index:
//   - rule.Keywords.Primary   → primary = true  (boost × 1.0)
//   - rule.Keywords.Secondary → primary = false (boost × 0.5)
//   - rule.Escalation.Keywords → primary = false (dùng để kiểm tra escalation)
func BuildKeywordIndex(rs *RuleSet) *KeywordIndex {
	kwMap := make(map[string][]kwEntry)

	for _, rule := range rs.Rules {
		addKWs := func(kws []string, primary bool) {
			for _, kw := range kws {
				if kw == "" {
					continue
				}
				lower := string(bytes.ToLower([]byte(kw)))
				// Cho phép cùng keyword xuất hiện ở nhiều rule (ví dụ: "email" trong
				// cả rule email lẫn rule contract). Mỗi rule track riêng.
				kwMap[lower] = append(kwMap[lower], kwEntry{
					ruleID:  rule.ID,
					primary: primary,
				})
			}
		}
		addKWs(rule.Keywords.Primary, true)
		addKWs(rule.Keywords.Secondary, false)
		addKWs(rule.Escalation.Keywords, false)
	}

	if len(kwMap) == 0 {
		return &KeywordIndex{kwMap: kwMap}
	}

	// Thu thập unique patterns (một keyword có thể thuộc nhiều rule).
	patterns := make([]string, 0, len(kwMap))
	for kw := range kwMap {
		patterns = append(patterns, kw)
	}

	trie := ahocorasick.NewTrieBuilder().
		AddStrings(patterns).
		Build()

	return &KeywordIndex{trie: trie, kwMap: kwMap}
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

// Scan tìm tất cả keyword trong chunk và trả về HitMap nhóm theo rule ID.
//
// Chunk được lowercase trước khi quét (case-insensitive matching).
// Allocation: ~len(chunk) bytes cho bản lowercase — chấp nhận được với chunk 64KB.
func (ki *KeywordIndex) Scan(chunk []byte) HitMap {
	hits := make(HitMap)
	if ki.trie == nil || len(chunk) == 0 {
		return hits
	}

	lower := bytes.ToLower(chunk) // case-insensitive: lowercase một lần, dùng nhiều lần
	emits := ki.trie.Match(lower)

	for _, emit := range emits {
		kw := string(emit.Match()) // keyword đã khớp (đã lowercase)
		entries, ok := ki.kwMap[kw]
		if !ok {
			continue
		}
		for _, entry := range entries {
			hits[entry.ruleID] = append(hits[entry.ruleID], KeywordHit{
				Keyword: kw,
				Offset:  emit.Pos(),
				Primary: entry.primary,
			})
		}
	}
	return hits
}

// HasAnyKeyword báo cáo chunk có chứa BẤT KỲ keyword nào từ bất kỳ rule nào không.
// Dùng làm bộ lọc tốc độ cao cấp toàn file trước khi đọc nội dung.
func (ki *KeywordIndex) HasAnyKeyword(chunk []byte) bool {
	if ki.trie == nil || len(chunk) == 0 {
		return false
	}
	lower := bytes.ToLower(chunk)
	return len(ki.trie.Match(lower)) > 0
}
