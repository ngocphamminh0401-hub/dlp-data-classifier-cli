# Báo cáo: Cơ chế giảm False Positive/Negative và cải thiện phân loại

## 1. Mục tiêu và phạm vi

Báo cáo tổng hợp toàn bộ thay đổi engine (`internal/engine/rules.go`, `regex.go`, `classifier.go`) và rule YAML (`rules/`) nhằm giảm sai lệch phân loại trên bộ dữ liệu ground-truth thật (`rawdata/`, 25.543 file — 4 domain tài chính-ngân hàng/y tế/nhân sự/bảo hiểm × 4 mức PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED). Toàn bộ số liệu trong báo cáo đo bằng `scripts/eval_confusion.go`, xác nhận trên dữ liệu thật trước khi áp dụng bất kỳ thay đổi nào.

Nguyên tắc xuyên suốt: **không đánh đổi mù quáng** — mọi cơ chế mới đều được kiểm chứng bằng cách đối chiếu file thật (không chỉ tin vào lý thuyết), và mọi tradeoff (accuracy PUBLIC tăng nhưng có thể làm giảm nhẹ recall ở tầng cao) đều được đo, trình bày rõ, và xin xác nhận trước khi giữ lại.

---

## 2. Cơ chế mới thêm vào engine

Kiến trúc gốc chỉ có: regex match → keyword context boost → validator (Luhn...) → ngưỡng confidence → gán level → compound rule nâng level. Đây là mô hình **"highest-sensitivity-wins"**: 1 match level cao, dù chỉ xuất hiện 1 lần và không có validator xác nhận, vẫn quyết định level của cả file. Đây là nguồn gốc của phần lớn over-classification.

7 cơ chế được thêm vào để giải quyết vấn đề này, theo thứ tự xuất hiện trong pipeline `matchAllPatterns` ([regex.go](../internal/engine/regex.go)):

### 2.1 `RulePattern.RequireKeywordWithin` (siết `context_required` xuống từng match)

`context_required: true` gốc chỉ kiểm tra keyword có mặt **đâu đó trong cả chunk** (`hits.HasRule`, chunk-wide). Với chunk lớn, 1 dòng "Ngày sinh:" ở đầu tài liệu đủ để biến MỌI số 4 chữ số (1900–2029) trong toàn bộ phần còn lại thành match "năm sinh". `RequireKeywordWithin` (byte) buộc keyword PRIMARY phải nằm gần **match cụ thể**, không chỉ có mặt trong chunk.

```yaml
# dob.yaml — pattern "D tháng M năm YYYY"
context_required: true
require_keyword_within: 40
```

### 2.2 `LevelGate` (đòi "bằng chứng thứ 2" trước khi giữ level cao)

Cơ chế trung tâm nhất, dùng trong hầu hết các fix. Corroboration được coi là đủ nếu 1 trong các điều kiện đúng: validator pass, match lặp lại ≥2 lần, có rule khác ≥CONFIDENTIAL trong cùng chunk, confidence vượt `MinConfidenceBypass`, hoặc (khi khai `RequiredCorroborationTags`) có match mang 1 trong các tag chỉ định. `StrictTagsOnly` loại bỏ hoàn toàn 4 điều kiện mặc định, chỉ còn tag cụ thể quyết định — cần thiết vì `count≥2` quá dễ đạt (2 pattern khác nhau khớp trùng 1 câu, hoặc 1 điều khoản boilerplate lặp cụm từ ở 2 mục khác nhau).

### 2.3 `NegationFilter` (phản ứng ngay với từ phủ định gần match)

RE2 (regex Go) không hỗ trợ lookbehind nên không thể loại trừ tiền tố phủ định ("không có...") ngay trong regex. `NegationFilter` bù đắp bằng cách quét cửa sổ ±N byte quanh match tìm trigger word, xử lý ngay tại thời điểm match (không chờ `LevelGate` đánh giá lại toàn chunk) — `suppress` loại hẳn match, `downgrade_to_gate` hạ về `LevelGate.FallbackLevel`.

### 2.4 `PlaceholderExclusion` (loại giá trị ví dụ/test/placeholder)

3 cơ chế độc lập: `ValueBlocklistPatterns` (regex anchor trên giá trị, hard reject — VD `"changeme"`), `KnownTestValues` (so khớp chính xác số thẻ test công khai của Stripe/VNPay sau khi chuẩn hóa), `DocContextDiscountKeywords`+`Factor` (giảm điểm mềm khi chunk có từ "hướng dẫn"/"ví dụ"/"template", không loại hẳn).

### 2.5 `VolumeEscalation` (nâng level theo quy mô, tách khỏi confidence từng match)

1 email lẻ chỉ INTERNAL, nhưng ≥50 email khác nhau trong cùng file (leak database) tự nâng CONFIDENTIAL, ≥200 nâng SECRET — độc lập với việc từng match riêng lẻ có "nhạy cảm" hay không.

### 2.6 `ProximityWindow` + bộ nhận diện ranh giới câu tiếng Việt

Thay "keyword có mặt trong cửa sổ N byte" (chunk-wide, lỏng) bằng "keyword thực sự gần **và cùng câu** với match". Phải viết riêng bộ nhận diện ranh giới câu tiếng Việt (`crossesSentenceBoundary`, `isSentenceEndDot`, [regex.go:348-512](../internal/engine/regex.go#L348-L512)) vì:
- dấu `.` là separator hàng nghìn ("25.000.000"), viết tắt hành chính ("TP.", "ThS.") — không phải luôn là hết câu;
- `\n` đơn lẻ do PDF/DOCX ngắt dòng/bảng — không phải hết câu, chỉ `\n\n` (ngắt đoạn thật) mới tính;
- văn bản dạng bảng/sao kê không có dấu câu chuẩn — nếu không tìm được ranh giới câu nào gần match, tự động bỏ qua yêu cầu `same_sentence_required` (fallback), ưu tiên không mất recall trên dữ liệu bảng.

### 2.7 `CompoundRule.ExcludeContextPatterns` (negative-signal cho compound rule)

Ngược hướng với `ContextConditions` (đòi có mặt): nếu chunk khớp bất kỳ pattern nào trong danh sách, compound rule KHÔNG kích hoạt dù mọi điều kiện khác đã thỏa. Dùng cho "Ethnicity/Religion + Health = SECRET" — loại trừ khi "Dân tộc" chỉ là trường nhân khẩu học thu thập thường quy trong mẫu bệnh án, không phải dấu hiệu bất thường.

### Thay đổi ở `classifier.go`

- `buildTagSet()` sửa để cộng dồn tag tùy chỉnh của rule (không chỉ suy ra từ category/prefix) — qua allowlist `compoundCustomTags` (kiểm soát, tránh rò rỉ tag không mong muốn vào compound rule khác).
- `applyCompoundRules()` nhận thêm `chunk []byte` để kiểm tra `ExcludeContextPatterns`.
- `RuleMatch.PatternIdx` được thêm để `LevelGate`/`NegationFilter` biết match thuộc pattern nào (áp dụng `applies_to_patterns` per-pattern).

---

## 3. Bảng tổng hợp toàn bộ rule đã sửa

| Rule | Cơ chế áp dụng | Vấn đề gốc | Tác động đo được |
|---|---|---|---|
| `health_001` | `level_gate` mở rộng 6→11 pattern, `required_corroboration_tags: [personal_identifier]` | Bảng giá dịch vụ y tế, lịch tiêm chủng công khai tự động CONFIDENTIAL/SECRET dù không gắn bệnh nhân cụ thể | −106 file (severity), +36 file (exact PUBLIC) |
| `income_001` | `required_corroboration_tags` + `strict_tags_only`, `fallback_level: PUBLIC` | Khoảng lương trong tin tuyển dụng đạt conf 0.97+, vượt `min_confidence_bypass` cũ vô điều kiện | −92 (severity) + 52 (exact) file |
| `insurance_context_001` | `strict_tags_only`, `fallback_level: PUBLIC` | Điều khoản/quy trình bảo hiểm công khai bị coi là hồ sơ claim thật | 204 file (severity, giai đoạn 1) + phần lớn trong 567 file (giai đoạn 2) |
| `fin_internal_chat_customer_data_001` | Sửa bug `fallback_level` trùng `rule.level` (gate vô nghĩa), giới hạn gate vào 1 pattern | Nhãn vai trò nhân viên ("(Trưởng nhóm)") đơn lẻ tự động CONFIDENTIAL | −20 file |
| `classified_doc_002` | Thêm `level_gate` (rule vốn chưa có) | `"BÍ MẬT KINH DOANH"` viết hoa trong tiêu đề chương nội quy lao động bị khớp thành nhãn phân loại tài liệu mật | −18 file |
| `biometric_001` | `negation_filter` theo từ vựng marketing (không dùng `personal_identifier` — bị nhiễm bởi FP của `dob_001`/`vn_name_001` trên cùng văn bản), `fallback_level: PUBLIC` | Brochure PR ngân hàng mô tả tính năng eKYC bị coi là có dữ liệu sinh trắc thật | −108 (severity) + phần trong 567 file (giai đoạn 2) |
| `fraud_transaction_flag_001` | `required_corroboration_tags: [financial_personal]` + `strict_tags_only`, `fallback_level: PUBLIC` | Điều khoản ToS ngân hàng boilerplate lặp "giao dịch bất thường" ≥2 lần tự thỏa `count≥2` | −14 (severity) + phần trong 567 file |
| `hr_disciplinary_health_investigation_001` | `required_corroboration_tags: [personal_identifier]` + `strict_tags_only` | "Hội đồng kỷ luật" đứng một mình trong điều khoản chính sách chung | −8 file (giảm 1 mức nghiêm trọng) |
| `dob_001` | `context_required` + `require_keyword_within: 40` cho pattern "D tháng M năm YYYY" | Ngày ban hành công văn ("Số: 37/2024, ngày 05 tháng 06 năm 2024") bị khớp thành ngày sinh, vô tình corroborate chéo với `health_001` | Sửa lỗi gốc, góp phần vào +36 file healthcare |
| `fraud_investigation_001` | `negation_filter action: suppress` cho pattern "án tích" | "Không có án tích" trong tiêu chí tuyển dụng bị coi là bằng chứng điều tra hình sự thật | Sửa lỗi gốc |
| `tax_code_business_001` | **Quyết định chính sách**: `level: INTERNAL → PUBLIC` | Mã số DN/thuế công khai theo Luật DN 2020 Điều 216, tra cứu miễn phí trên Cổng ĐKDN quốc gia | **+253 file** (tác động lớn nhất toàn bộ 2 giai đoạn) |
| `phone_001` | `override_level: PUBLIC` cho pattern hotline 1800/1900 | Tín hiệu cấu trúc thuần túy — đầu số 1800/1900 không bao giờ là số cá nhân theo quy hoạch số | +8 file, an toàn tuyệt đối |
| `fin_account_statement_001` | `negation_filter action: suppress` khi có tín hiệu giá + đơn vị | "Sao kê tài khoản định kỳ 5.500 VNĐ/lần" là dòng biểu phí dịch vụ, không phải sao kê thật | −21 file |
| `bank_account_001`, `vn_id_001`, `passport_001`, `tax_code_personal_001`, `social_insurance_001` | Thêm `min_confidence_bypass` | Match confidence rất cao (cụm đặc trưng, nhiều keyword) vẫn bị `level_gate` hạ nhầm dù đủ mạnh để tự đứng | Giảm false-negative cho match thật sự mạnh |

### Compound rule

| Thay đổi | Lý do |
|---|---|
| `pii` → `pii_strong`, `financial` → `financial_personal` trên 5 compound condition | Tag gốc quá rộng, gộp cả rule yếu (INTERNAL 0.35–0.45) lẫn rule mạnh (SECRET 0.95) — 1 email cấp thấp cũng đủ kích hoạt compound SECRET |
| `credit_card` → `credit_card_001` | Tham chiếu tag mơ hồ, sửa về đúng rule ID |
| Thêm `exclude_context_patterns` cho "Ethnicity/Religion + Health = SECRET" | Dân tộc là trường nhân khẩu học thu thập thường quy trong mẫu bệnh án VN |
| Gỡ hẳn "Health + Financial = SECRET" (quá rộng) | Hợp đồng lao động có mục BHYT + lương cũng tự nổ — thay bằng "Health + Insurance Context = SECRET" (điều kiện thứ 3 thu hẹp domain) |

---

## 4. Kết quả đo lường tổng thể

| Ground truth | Trước (baseline gốc) | Sau (hiện tại) | Δ |
|---|---|---|---|
| PUBLIC | 59.7% | **73.6%** | **+13.9pp** |
| INTERNAL | 83.7% | 86.4% | +2.7pp |
| CONFIDENTIAL | 87.2% | 87.2% | 0 (không đổi) |
| TOP_SECRET | 86.7% | 86.6% | −0.1pp (trong ngưỡng nhiễu) |
| **Tổng thể** | **79.3%** | **83.4%** | **+4.1pp** |

Over-classify (chấm cao hơn ground truth): 14.0% → 9.6%. Under-classify: 6.7% → 6.9% (tăng nhẹ, chủ yếu từ các đánh đổi đã duyệt bên dưới).

### Đánh đổi đã biết và được duyệt (không phải regression ẩn)

- **4 file lương thật** (thông báo lương qua chat nội bộ, không trích xuất được tên/CCCD gần đó) tụt từ CONFIDENTIAL xuống PUBLIC — đổi lấy 59+ file tin tuyển dụng PUBLIC được sửa đúng.
- **2 file hồ sơ thẩm tra lý lịch chính trị** (hr__top_secret) giảm từ RESTRICTED xuống CONFIDENTIAL — do `negation_filter` "không có án tích" áp cả vào form thẩm tra thật, không chỉ tiêu chí tuyển dụng.
- **~30 file** SOP/quy trình nội bộ (bảo hiểm, y tế) không có tín hiệu cá nhân nào khác giảm từ INTERNAL xuống PUBLIC — hệ quả trực tiếp của việc hạ `fallback_level`.
- **~7 file** hợp đồng B2B thật (giữa 2 tổ chức) mất tín hiệu duy nhất khi `tax_code_business_001` chuyển sang PUBLIC.

Tổng tất cả đánh đổi: ~43 file trên 25.543 (0.17%), đổi lấy hơn 1.400 file được xếp đúng hơn.

---

## 5. Đánh giá khả năng cải thiện

### Đã đạt được tốt

- **Severity reduction** (giai đoạn 1): giảm gần 50% số file PUBLIC bị đẩy lên mức nghiêm trọng (CONFIDENTIAL/RESTRICTED) — đây là rủi ro cấp bách nhất về UX/niềm tin hệ thống, được ưu tiên xử lý trước và đạt hiệu quả rõ rệt.
- **Exact-match resolution** (giai đoạn 2): giải quyết tận gốc "sàn cứng INTERNAL" — nhiều rule tự đặt floor bảo vệ dù hoàn toàn không có bằng chứng, khiến PUBLIC không bao giờ đạt exact-match dù severity đã giảm. Quyết định chính sách (`tax_code_business_001`) đóng góp gần 1/3 tổng cải thiện — cho thấy đôi khi vấn đề không phải kỹ thuật mà là giả định chính sách sai.
- **CONFIDENTIAL/TOP_SECRET giữ nguyên gần như tuyệt đối** dù sửa 15 rule khác nhau — chứng tỏ phương pháp "verify bằng dữ liệu thật trước khi giữ lại thay đổi" (không chỉ tin lý thuyết) hiệu quả trong việc tránh lan truyền lỗi sang các tầng khác.

### Giới hạn đã chạm phải (2 rule lớn nhất bị bỏ qua có chủ đích)

`vn_name_001` (tên trong khối chữ ký, ~156 file tiềm năng) và `email_001` (email liên hệ/hotline, ~96 file tiềm năng) đều được điều tra kỹ nhưng **không áp dụng** vì kiểm chứng cho thấy 18–40% file INTERNAL/CONFIDENTIAL **thật** dùng đúng cùng từ vựng cục bộ với file PUBLIC:

- "(Ký, ghi rõ họ tên)" xuất hiện giống hệt trong hợp đồng mẫu công khai VÀ hợp đồng lao động thật.
- "Liên hệ:"/"Hotline:" xuất hiện giống hệt trong email hỗ trợ công khai VÀ email đào tạo nội bộ ("Email nội bộ: training@...", "Tài liệu dành cho nội bộ").

Đây không phải giới hạn của 1 kỹ thuật cụ thể mà là **giới hạn kiến trúc**: mọi cơ chế hiện có (`level_gate`, `negation_filter`, `proximity_window`) hoạt động trên cửa sổ vài chục–vài trăm byte quanh 1 match. Sự khác biệt thật giữa 2 loại tài liệu trên nằm ở **cấp độ toàn văn bản** (thông cáo báo chí vs. tài liệu vận hành nội bộ) — không có tín hiệu cục bộ nào tách được.

Một phát hiện phụ đáng chú ý: `vn_name_001` **không nhận diện được tên người khi xuất hiện trong bảng dữ liệu dạng cột** (VD `"1 Phạm Đình Khánh CH10199268361 02/04/2024 ... I10 - Tăng huyết áp"`) — chỉ nhận tên sau nhãn "Họ tên:" hoặc trong câu văn thường. Đây là nguyên nhân trực tiếp khiến 1 thử nghiệm gate chặt hơn cho `health_001` (`strict_tags_only`) bị hoàn tác do gây regression 49 file — không phải gate sai, mà là rule phụ thuộc (`vn_name_001`) có lỗ hổng.

---

## 6. Hướng phát triển tiếp theo

### Ưu tiên cao — mở khóa lại cơ hội đã bỏ lỡ

1. **Mở rộng `vn_name_001` nhận diện tên dạng bảng** (cột `STT | Tên | Mã BN | ...`). Sau khi vá, có thể bật lại `strict_tags_only` cho `health_001` một cách an toàn (ước tính thêm ~90 file PUBLIC, hiện đang bỏ ngỏ do quyết định thận trọng).
2. **Tín hiệu cấp toàn văn bản (document-type signal)** — hướng giải quyết thật cho `vn_name_001`/`email_001`: một heuristic ở cấp file (không phải cấp match) phân biệt "văn bản công khai" (thông cáo báo chí, tiêu đề PR, cấu trúc mở đầu chuẩn) với "văn bản nội bộ" (nhãn "Tài liệu dành cho nội bộ", ngữ cảnh chat nội bộ, ký hiệu công văn nội bộ). Có thể triển khai như 1 pass tiền xử lý gán "document_context" tag cho cả chunk, rồi các rule khác tham chiếu qua `required_corroboration_tags` — tái dùng được cơ chế `LevelGate` đã có, chỉ cần thêm nguồn tag mới.

### Ưu tiên trung bình — dọn dẹp kỹ thuật

3. **Dead field trong `KeywordLogic`/`FPReduction`**: `MinPrimary`, `ConfidencePerKeyword`, `MaxConfidence`, `LuhnRequired` được khai trong nhiều rule YAML nhưng chưa từng được engine đọc — hoặc xóa khỏi YAML (giảm nhiễu), hoặc nối vào engine nếu có giá trị thật.
4. **Chuẩn hóa việc `negation_filter`/`level_gate` không tự động dùng chung `fallback_level`** — hiện tại nhiều rule phải tự set lại `fallback_level` phù hợp cho từng use-case, dễ lặp lại bug "fallback trùng rule.level" (đã gặp ở `fin_internal_chat_customer_data_001`). Cân nhắc validate ở `loadRule()`: cảnh báo nếu `fallback_level == rule.level`.

### Ưu tiên thấp — khai thác dữ liệu chưa dùng

5. **Domain khác (finance_banking/hr/insurance) PUBLIC** chưa được rà soát bằng đúng phương pháp rule-attribution đã áp dụng cho healthcare ở vòng cuối — có thể còn dư địa cải thiện tương tự.
6. **`tax_code_business_001` dạng khác** — quyết định chính sách hiện tại chỉ áp cho mã số 10 số. Cân nhắc rà soát các trường "công khai theo luật" tương tự khác (VD số đăng ký kinh doanh hộ cá thể, mã ngành nghề) nếu có rule riêng.

---

## Phụ lục: file/commit liên quan

- Commit `54ae4ae` — baseline gốc trước toàn bộ báo cáo này.
- Commit `b1e9ce4` — `min_confidence_bypass`, `proximity_window`, giai đoạn 1 (severity reduction, 9 rule).
- Commit `574108b` — giai đoạn 2 (policy + fallback_level, 8 rule).
- Công cụ đo: `scripts/eval_confusion.go --root rawdata [--domain <domain>]`.
- Engine: [`internal/engine/rules.go`](../internal/engine/rules.go) (schema + load/validate), [`internal/engine/regex.go`](../internal/engine/regex.go) (hot-path matching/scoring), [`internal/engine/classifier.go`](../internal/engine/classifier.go) (orchestration + compound rules).
