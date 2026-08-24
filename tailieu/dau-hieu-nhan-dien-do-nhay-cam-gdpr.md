# Bổ sung: Dấu hiệu nhận diện độ nhạy cảm dựa trên GDPR (đối chiếu Nghị định 13/2023/NĐ-CP)

**Mục đích:** Tài liệu này bổ sung cho bản kế hoạch trước, cung cấp các **dấu hiệu/tiêu chí cụ thể** để gán nhãn 4 cấp (Công khai/Nội bộ/Mật/Tối mật), dựa trên các định nghĩa pháp lý trong GDPR (EU) và đối chiếu với Nghị định 13/2023/NĐ-CP của Việt Nam. Mục tiêu là các dấu hiệu này có thể dùng trực tiếp làm **input định nghĩa nhãn cho mô hình LLM** (system prompt/annotation guideline), không chỉ là mô tả chung chung.

**Team vui lòng review lại toàn bộ trước khi xác nhận** — đặc biệt các điểm được đánh dấu ⚠️ vì đây là những chỗ GDPR/NĐ13 gợi ý nâng cấp so với bản nháp định nghĩa ban đầu.

---

## 1. Cơ sở pháp lý được tham chiếu

| Nguồn | Nội dung dùng để tinh chỉnh |
|---|---|
| **GDPR Điều 4(1)** | Định nghĩa "dữ liệu cá nhân": thông tin liên quan đến một cá nhân **định danh được** — trực tiếp (tên, số CMND/CCCD) hoặc gián tiếp (định vị, mã định danh online, yếu tố thể chất/sinh lý/di truyền/tâm lý/kinh tế/văn hóa/xã hội) |
| **GDPR Điều 4(13)(14)(15)** | Định nghĩa "dữ liệu di truyền", "dữ liệu sinh trắc học", "dữ liệu sức khỏe" |
| **GDPR Điều 9** | Danh mục "special category data" — cấm xử lý trừ khi có ngoại lệ (consent tường minh, mục đích y tế, việc làm...) |
| **GDPR Điều 10** | Dữ liệu về án tích/hành vi phạm tội — chỉ được xử lý dưới sự kiểm soát của cơ quan nhà nước có thẩm quyền |
| **GDPR Điều 35 & Recital liên quan** | Yếu tố khuếch đại rủi ro: xử lý **quy mô lớn** dữ liệu đặc biệt nhạy cảm, ra quyết định tự động có ảnh hưởng pháp lý, giám sát hệ thống — dùng để phân biệt Mật vs Tối mật khi cùng loại dữ liệu |
| **GDPR Điều 4(5)** | Pseudonymisation — dữ liệu đã được ẩn danh hóa một phần có thể **hạ cấp** độ nhạy cảm nếu không thể định danh trực tiếp |
| **Nghị định 13/2023/NĐ-CP, Điều 2 khoản 3 & 4** | Định nghĩa "dữ liệu cá nhân cơ bản" và "dữ liệu cá nhân nhạy cảm" theo pháp luật Việt Nam — đối chiếu để bổ sung các mục GDPR không có nhưng luật VN có |

**Điểm khác biệt quan trọng cần lưu ý:** GDPR Điều 9 **không liệt kê dữ liệu tài chính/ngân hàng** là "special category" (dữ liệu tài chính chỉ được bảo vệ qua các nguyên tắc chung + Điều 32 bảo mật). Ngược lại, **Nghị định 13/2023 liệt kê rõ "dữ liệu khách hàng của tổ chức tín dụng" (số tài khoản, số dư, giao dịch...) là dữ liệu nhạy cảm**. Vì bộ dữ liệu này phục vụ tổ chức tại Việt Nam, khuyến nghị **ưu tiên theo chuẩn nghiêm ngặt hơn (NĐ13)** cho lĩnh vực tài chính-ngân hàng.

---

## 2. Khung 3 lớp dấu hiệu để gán nhãn

Đề xuất mô hình hóa việc gán nhãn theo 3 lớp câu hỏi tuần tự — LLM (hoặc annotator) trả lời lần lượt để suy ra cấp độ, thay vì đoán trực tiếp:

### Lớp 0 — Có phải dữ liệu cá nhân không?
- Văn bản có nhắc đến một cá nhân **định danh được** không (trực tiếp: họ tên, CCCD, SĐT, email; hoặc gián tiếp: mã nhân viên + chức danh cụ thể, địa chỉ + ngày sinh)?
- Nếu **không** → tối đa là **Công khai** hoặc **Nội bộ** (tùy nguồn gốc/mục đích lưu hành).
- Nếu **có** → chuyển sang Lớp 1.

### Lớp 1 — Có thuộc "dữ liệu nhạy cảm" theo Điều 9 GDPR / Điều 2.4 NĐ13 không?
Nếu văn bản chứa **bất kỳ** dấu hiệu nào trong bảng mục 3 bên dưới → tối thiểu **Mật**, và nếu kết hợp với chi tiết cụ thể/định lượng cao → **Tối mật**.
Nếu không thuộc nhóm nhạy cảm đặc biệt nhưng vẫn có PII cơ bản (tên, SĐT, địa chỉ, lương...) → **Mật**.

### Lớp 2 — Yếu tố khuếch đại (nâng từ Mật lên Tối mật)
Ngay cả cùng một loại dữ liệu, mức độ rủi ro tăng lên (nên gán **Tối mật** thay vì Mật) khi có:
- **Quy mô lớn**: văn bản chứa dữ liệu của **nhiều cá nhân cùng lúc** (danh sách/bảng tổng hợp) thay vì 1 hồ sơ đơn lẻ.
- **Có thể dùng để ra quyết định tự động/có hệ quả pháp lý**: ví dụ dữ liệu dùng để tính phí bảo hiểm, chấm điểm tín dụng, sa thải nhân sự.
- **Có mã xác thực/bí mật đi kèm**: OTP, mật khẩu, CVV, khóa API — luôn là Tối mật bất kể ngữ cảnh.
- **Liên quan điều tra/tố tụng**: theo Điều 10 GDPR, dữ liệu án tích/hành vi phạm tội luôn ở mức cao nhất.

### Lớp giảm nhẹ — Có dấu hiệu ẩn danh hóa không?
Nếu dữ liệu đã được thay thế định danh trực tiếp (tên → mã hồ sơ, số liệu đã tổng hợp/thống kê, không thể truy ngược cá nhân cụ thể) → có thể **hạ 1 cấp** so với đánh giá ban đầu (theo tinh thần Điều 4(5) GDPR về pseudonymisation — lưu ý pseudonymisation KHÔNG đồng nghĩa với ẩn danh hoàn toàn, nên chỉ hạ cấp khi thực sự không thể định danh ngược lại bằng thông tin có trong văn bản).

---

## 3. Bảng dấu hiệu/từ khóa nhận diện theo từng nhóm dữ liệu nhạy cảm

Bảng này dùng làm "checklist tín hiệu" — có thể đưa thẳng vào system prompt của mô hình phân loại hoặc dùng làm rule hỗ trợ gán nhãn.

| Nhóm (theo GDPR Art.9 / NĐ13 Đ.2.4) | Dấu hiệu/từ khóa tiếng Việt gợi ý | Domain liên quan nhiều nhất |
|---|---|---|
| Chủng tộc, dân tộc | "dân tộc", "chủng tộc", "dân tộc thiểu số" | HR (trường "Dân tộc" trong sơ yếu lý lịch/CV) |
| Quan điểm chính trị | "đảng viên", "lý lịch chính trị", "thành phần gia đình", "quan điểm chính trị" | HR (hồ sơ lý lịch cán bộ) |
| Tôn giáo, tín ngưỡng | "tôn giáo", "tín ngưỡng", "đạo..." | HR (trường "Tôn giáo" trong CV/sơ yếu lý lịch) |
| Thành viên công đoàn | "đoàn viên công đoàn", "công đoàn cơ sở" | HR |
| Dữ liệu di truyền | "ADN", "gen", "di truyền", "xét nghiệm gen" | Y tế, Bảo hiểm (thẩm định) |
| Dữ liệu sinh trắc học | "vân tay", "khuôn mặt", "mống mắt", "nhận diện sinh trắc", "chữ ký số sinh trắc" | Y tế, Tài chính-ngân hàng (eKYC) |
| Dữ liệu sức khỏe | "chẩn đoán", "bệnh án", "tình trạng sức khỏe", "kết quả xét nghiệm", "đơn thuốc", mã ICD-10, tên bệnh cụ thể | Y tế, Bảo hiểm (hồ sơ claim), HR (nghỉ ốm/khám sức khỏe định kỳ) |
| Đời sống tình dục/xu hướng tính dục | (hiếm gặp trong văn bản nghiệp vụ — nếu xuất hiện, luôn gán Tối mật) | Y tế |
| Dữ liệu về tội phạm/hành vi phạm tội | "tiền án", "tiền sự", "bị can", "khởi tố", "điều tra hình sự", "án tích", "giao dịch đáng ngờ", "rửa tiền", "gian lận" | Tài chính-ngân hàng (AML), Bảo hiểm (điều tra gian lận) |
| Dữ liệu tài khoản/giao dịch ngân hàng (riêng theo NĐ13, GDPR không liệt kê) | Số tài khoản, số dư, lịch sử giao dịch, số thẻ, sao kê | Tài chính-ngân hàng |
| Dữ liệu vị trí (theo NĐ13) | Tọa độ định vị, lịch sử di chuyển qua GPS/dịch vụ định vị | Tài chính-ngân hàng (chống gian lận), Bảo hiểm |
| Mã xác thực/bí mật (luôn Tối mật) | OTP, mật khẩu, CVV, mã PIN, khóa API, mã truy cập hệ thống | Tất cả 4 lĩnh vực |

---

## 4. Cập nhật đề xuất cho 16 ô định nghĩa (so với bản kế hoạch trước)

Chỉ liệt kê những điểm **thay đổi/làm rõ thêm** so với bản trước — các phần còn lại giữ nguyên.

### 4.1. Nhân sự (HR) ⚠️
- Hồ sơ CV/sơ yếu lý lịch tiếng Việt truyền thống thường có các trường **"Dân tộc"**, **"Tôn giáo"**, đôi khi **"Thành phần gia đình"/"Đảng viên"**. Theo Điều 9 GDPR, đây là **special category data** (chủng tộc, tôn giáo, quan điểm chính trị) — **đề xuất nâng các hồ sơ có đủ các trường này lên Tối mật**, thay vì chỉ xếp Mật như bản nháp ban đầu, ngay cả khi văn bản trông giống "hồ sơ nhân sự thông thường".
- Hồ sơ có dữ liệu sức khỏe nhân viên (khám sức khỏe định kỳ, nghỉ ốm dài hạn, hồ sơ tai nạn lao động) → Tối mật (thuộc nhóm dữ liệu sức khỏe).

### 4.2. Y tế ⚠️
- Giữ nguyên định hướng nhưng làm rõ: **bất kỳ hồ sơ nào có tên bệnh nhân + chẩn đoán cụ thể đều đã đạt ngưỡng "dữ liệu sức khỏe" theo Điều 9** → tối thiểu Mật (không phải chỉ khi bệnh "nhạy cảm" như trong bản trước). Mức Tối mật dành riêng cho các bệnh/tình trạng có nguy cơ kỳ thị cao (HIV, tâm thần, sản khoa/phá thai, bệnh di truyền) hoặc khi có **quy mô lớn** (danh sách nhiều bệnh nhân).

### 4.3. Bảo hiểm
- Hồ sơ bồi thường có chẩn đoán y tế = giao giữa 2 nhóm (sức khỏe + tài chính cá nhân) → luôn xếp Tối mật theo nguyên tắc Lớp 2 (yếu tố khuếch đại: dùng để ra quyết định tài chính).
- Hồ sơ điều tra gian lận bảo hiểm → áp dụng logic Điều 10 GDPR (dữ liệu liên quan hành vi vi phạm) → Tối mật.

### 4.4. Tài chính - Ngân hàng ⚠️
- Theo NĐ13 (không phải GDPR), **số tài khoản/số dư/giao dịch đã đủ điều kiện là "dữ liệu nhạy cảm"** ngay cả khi không có thêm yếu tố nào khác — đề xuất **nâng ngưỡng "Mật" xuống thấp hơn** so với bản trước (trước đây chỉ xếp Mật khi có tên + CCCD + SĐT; nay chỉ cần số tài khoản/sao kê + tên là đủ vào Mật).
- Số thẻ đầy đủ + CVV/OTP/mật khẩu → luôn Tối mật (mã xác thực, Lớp 2).
- Báo cáo giao dịch đáng ngờ/hồ sơ AML → Tối mật (dữ liệu tội phạm theo Điều 10).

---

## 5. Đề xuất bổ sung trường (field) vào schema JSONL

Để mô hình học được các dấu hiệu này thay vì chỉ học nhãn cuối, khuyến nghị gắn thêm metadata khi sinh/gán nhãn (phục vụ debug, phân tích lỗi, và có thể dùng làm auxiliary label khi huấn luyện):

```json
{
  "...": "...(các field cũ giữ nguyên)...",
  "special_category_signals": ["health_data", "ethnicity", "religion", "banking_account", "criminal_data"],
  "identifiability": "direct | indirect | pseudonymized",
  "scale_hint": "single_individual | multiple_individuals | large_scale_list",
  "has_auth_secret": false
}
```

Việc này cũng giúp sau này dễ **audit** vì sao một mẫu được gán nhãn X — quan trọng khi cần giải trình với đội pháp chế/tuân thủ.

---

## 6. Việc cần team xác nhận

1. Có đồng ý nâng hồ sơ HR có trường Dân tộc/Tôn giáo/Đảng viên lên **Tối mật** thay vì Mật không? (mục 4.1)
2. Có đồng ý hạ ngưỡng vào "Mật" cho dữ liệu tài khoản ngân hàng theo NĐ13 (không cần đủ tên+CCCD+SĐT mới vào Mật) không? (mục 4.4)
3. Ngưỡng "quy mô lớn" (Lớp 2) nên định lượng cụ thể là bao nhiêu cá nhân/bản ghi trong 1 văn bản (ví dụ: >10 người → coi là large_scale)?
4. Có cần bổ sung thêm nhóm dữ liệu nào đặc thù ngành mà GDPR/NĐ13 chưa liệt kê nhưng thực tế nghiệp vụ VNPT-VCI hay gặp không?

---

*Tài liệu này bổ sung cho bản kế hoạch gốc (ke-hoach-bo-du-lieu-phan-loai-nhay-cam.md). Sau khi team xác nhận các điểm ở mục 6, mình sẽ cập nhật lại toàn bộ 16 ô định nghĩa thành bản final trước khi chạy pilot sinh dữ liệu.*

## Nguồn tham khảo
- [Art. 4 GDPR – Definitions](https://gdpr-info.eu/art-4-gdpr/)
- [Art. 9 GDPR – Processing of special categories of personal data](https://gdpr-info.eu/art-9-gdpr/)
- [Art. 10 GDPR – Processing of personal data relating to criminal convictions and offences](https://gdpr-info.eu/art-10-gdpr/)
- [Recital 51 GDPR](https://gdpr-info.eu/recitals/no-51/)
- [Art. 35 GDPR – Data protection impact assessment](https://gdpr-info.eu/art-35-gdpr/)
- [Toàn văn Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-dinh-13-2023-nd-cp-bao-ve-du-lieu-ca-nhan-119230516104357809.htm)
