# QUY TẮC VIẾT RULE & COMPOUND RULE — DLP CLASSIFIER
> Mục tiêu: accuracy >80% trên 4 domain (y tế, tài chính-ngân hàng, bảo hiểm, nhân sự), FP thấp, dễ mở rộng.

---

## A. TRƯỚC KHI VIẾT 1 RULE ĐƠN — TRẢ LỜI 3 CÂU HỎI

1. **Đặc thù hay generic?** Format cụ thể/mã số (CCCD, số thẻ) = đặc thù. Cụm từ chung (VD "báo cáo tổng hợp") = generic.
2. **Tự đủ nghĩa hay cần ngữ cảnh?** Số thẻ đúng Luhn = tự đủ nghĩa. Từ đơn lẻ như "hạn mức" = cần keyword đi kèm mới có ý nghĩa nghiệp vụ.
3. **Rủi ro khi lộ là gì, actor gây hại là ai?** → quyết định level (xem mục C).

**Quy tắc lõi:** độ đặc thù của pattern **tỉ lệ nghịch** với mức cần gate. Càng đặc thù/hiếm gặp ngoài nội bộ → càng ít cần gate. Càng generic → bắt buộc gate hoặc fallback level thấp hơn.

---

## B. THIẾT KẾ PATTERN (vì RE2 không có lookaround)

- **Không** cố nhồi phủ định vào 1 regex. **Tách thành 2+ pattern** trong cùng rule:
  - Nhánh cụ thể, khó phủ định (số liệu, tên riêng, mã cụ thể) → giữ level gốc.
  - Nhánh chính sách chung, dễ đứng sau "không có/không yêu cầu" → hạ 1 bậc hoặc bắt buộc `level_gate`.
- Dùng **keyword layer** (`primary`/`secondary` + `false_positive_reduction`: `min_context_window`, `exclude_if_no_keywords`) để bù cho việc thiếu lookaround — ép buộc phải có ngữ cảnh nghiệp vụ đặc thù đi kèm.

---

## C. GÁN LEVEL — DỰA RỦI RO THỰC, KHÔNG DỰA CẢM GIÁC

| Nhóm | Đặc điểm | Xử lý gate |
|---|---|---|
| **Luôn SECRET không gate** | Lộ 1 lần là đủ gây hại trực tiếp, không khắc phục được: credentials, OTP/PIN, sinh trắc học thật, CVV, HEALTH_RESTRICTED | **Cố ý không gate** — gate sẽ giảm recall trên case nguy hiểm nhất |
| **Cần gate/corroboration** | Chỉ nguy hiểm khi đủ độ tin cậy: tên người, ngày sinh, IP nội bộ đơn lẻ | `level_gate`: ≥2 lần khớp HOẶC rule khác ≥ CONFIDENTIAL cùng chunk |
| **Rủi ro theo quy mô** | Rò 1 record vs rò hàng loạt là 2 loại rủi ro khác nhau | `volume_escalation` (không lẫn với level_gate) |

Mỗi level phải trích được **căn cứ** (NĐ13/2023, PCI-DSS, GDPR Điều X...), không suy diễn cảm tính.

---

## D. BA THAM SỐ HIỆU CHỈNH — DÙNG ĐÚNG VAI TRÒ, KHÔNG BÙ TRỪ LẪN NHAU

| Tham số | Vai trò | Khi chỉnh thấp |
|---|---|---|
| `confidence` (per-pattern) | Độ tin cậy nội tại của regex | Regex mơ hồ, nhiều biến thể (0.65–0.70) |
| `weight` (per-rule) | Độ tin cậy cả rule so với `MinConfidence` engine | Rule dựa nhiều vào keyword suy luận, không phải định danh trực tiếp |
| `context_required` + `false_positive_reduction` | Bắt buộc ngữ cảnh nghiệp vụ | Pattern là từ/cụm đơn lẻ, generic |

**Cấm:** nâng `weight` để "cứu" regex quá rộng — phải sửa regex hoặc thêm keyword gate.

---

## E. PRIORITY

- Trong cùng 1 level, pattern càng ít FP (có validator như Luhn, format cụ thể) → priority càng cao.
- Priority **không nhất thiết** theo thứ hạng level (CVV priority 98 > classified_doc priority 95 dù cùng SECRET, vì CVV ít FP hơn).

---

## F. TRÁNH CHỒNG LẤN RULE

- Trước khi tạo rule mới: đã có rule nào cùng tag/category, keyword tương tự chưa? Nếu có → mở rộng pattern rule cũ, không tạo rule trùng.
- Chỉ tách rule mới khi **field structure khác nhau thật sự** (VD: cần gate khác nhau — cụm từ đặc thù không cần gate trong khi cụm từ chung cùng category cần gate).

---

## G. COMPOUND RULE — CHECKLIST BẮT BUỘC (4 bước, theo thứ tự)

### G1. Có căn cứ compliance/rủi ro cụ thể không?
Viết được câu: *"Điều X của quy định Y: tổ hợp [A+B] cấu thành [tổn hại cụ thể], tổn hại này không tồn tại ở A hoặc B riêng lẻ."*
- ✅ Đạt: Credit card+CVV → PCI-DSS 3.3.1 (gian lận thẻ tức thời). Email+Phone+DOB → GDPR Recital 26 (re-identification).
- ❌ Không đạt → **không tạo compound**: "2 category CONFIDENTIAL cùng xuất hiện" không phải căn cứ. (Case đã gỡ: Health+Financial=SECRET — fire nhầm trên hợp đồng lao động có mục BHYT+lương.)

### G2. Tag phải hẹp nhất có thể
- Liệt kê **mọi** rule đơn rơi vào tag định dùng → hỏi: "nếu 2 rule bất kỳ trong đó cùng match, kết luận nâng level còn đúng không?"
- Thứ tự ưu tiên hẹp dần: `ruleID đầy đủ` > `category_prefix` (VD `org_contract`) > `category` (VD `org` — chỉ dùng khi thực sự muốn "bất kỳ loại nào cũng được", hiếm khi đúng).
- Ví dụ lỗi: dùng tag `org` cho "Contract+PII" sẽ khiến watermark+email (đều INTERNAL, không liên quan hợp đồng) vô tình nâng CONFIDENTIAL.

### G3. Điều kiện nào trỏ vào rule có `level_gate`/`fallback_level` → BẮT BUỘC set `min_component_level`
- Compound mặc định chỉ check "có match" (tag có mặt), **không** check level thật sau gate.
- Thiếu `min_component_level` → compound "hồi sinh" match đã bị gate hạ, vô hiệu hóa gate.
- Quy tắc: `min_component_level` = level gốc (pre-gate) của rule đó.

### G4. Engine có no-downgrade không? Nếu compound trùng level với rule gốc đã đạt sẵn (VD cả 2 điều kiện đã tự SECRET) → compound đó **không đổi level thật**, chỉ có giá trị khi gắn `violation_type`/`alert_priority` để phân luồng workflow. Nếu không gắn gì thêm → compound đó thừa, không nên tạo.

---

## H. GHI RATIONALE — BẮT BUỘC

Mọi quyết định không hiển nhiên (không gate dù trông generic, override level, đảo ngược quyết định cũ, gỡ compound) phải có comment nêu rõ **căn cứ dữ liệu thật hoặc quy định**, không phải trực giác — để người/AI sau không sửa nhầm lại.

---

## I. CHECKLIST NHANH — TRƯỚC KHI MERGE 1 RULE ĐƠN

- [x] Level có căn cứ quy định/rủi ro thực, không phải cảm tính?
- [x] Pattern đã tách theo khả năng bị phủ định/generic hóa chưa?
- [x] `context_required`/keyword gate cần không, dựa độ đặc thù cụm từ?
- [x] `level_gate` có cần không? Có trùng logic với rule tương tự đã có không?
- [x] `volume_escalation` có ý nghĩa với loại dữ liệu này không (danh sách/bảng: có; đơn lẻ như CCCD: không)?
- [x] Priority đặt đúng theo độ tin cậy tương đối trong cùng level?
- [x] Đã test trên ≥1 case FP tiềm năng (văn bản PUBLIC chứa cụm từ tương tự)?
- [x] Có comment rationale cho mọi quyết định không hiển nhiên?

## J. CHECKLIST NHANH — TRƯỚC KHI MERGE 1 COMPOUND RULE

- [x] Có câu căn cứ compliance/rủi ro cụ thể (G1)?
- [x] Tag dùng trong `conditions` đã hẹp nhất có thể (G2)?
- [x] Đã set `min_component_level` cho mọi điều kiện trỏ vào rule có gate (G3)?
- [x] Nếu trùng level với rule gốc dưới no-downgrade, đã gắn `violation_type`/`alert_priority` chưa, hay compound này thừa (G4)?
- [x] Đã test trên case "hợp pháp phổ biến" (near-miss, VD hợp đồng lao động chuẩn) để chắc không tự nổ nhầm?

---

## K. VÒNG LẶP TỐI ƯU KHI CHẠY TRÊN TẬP TEST

1. Chạy rule set → lấy toàn bộ FP/FN kèm rule ID đã fire.
2. FP → xác định đúng 1 nguyên nhân (pattern rộng? thiếu context_required? thiếu gate? tag compound quá rộng?) → sửa đúng điểm đó, không nới lỏng tràn lan.
3. FN → thiếu pattern/keyword? gate hạ nhầm case đúng phải cao? weight/confidence chưa đủ vượt `MinConfidence`? → cân nhắc thêm compound có căn cứ (qua G1) hoặc override_level ở rule gốc.
4. Re-run **toàn bộ golden regression set** (không chỉ case vừa sửa) để tránh regression sang domain khác.
5. Ưu tiên đo riêng: **recall trên RESTRICTED/SECRET thật phải >90%** (under-classify nguy hiểm hơn over-classify), rồi mới tối ưu accuracy tổng thể lên >80%.
