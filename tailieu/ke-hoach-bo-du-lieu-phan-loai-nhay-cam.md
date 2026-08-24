# Kế hoạch xây dựng bộ dữ liệu huấn luyện mô hình phân loại văn bản theo mức độ nhạy cảm

**Đơn vị:** Trung tâm An toàn thông tin VNPT - VCI
**Mục đích sử dụng:** Phục vụ hệ thống DLP (Data Loss Prevention) / rà soát rò rỉ dữ liệu nội bộ
**Lĩnh vực bao phủ:** Bảo hiểm, Y tế, Tài chính - Ngân hàng, Nhân sự
**Ngày lập kế hoạch:** 05/08/2026

---

## 1. Mục tiêu và phạm vi

Xây dựng một bộ dữ liệu văn bản tiếng Việt, có gán nhãn mức độ nhạy cảm, dùng để huấn luyện (fine-tune hoặc prompt-tune) một mô hình LLM phân loại văn bản. Mô hình sau khi huấn luyện sẽ được dùng trong hệ thống DLP để tự động phát hiện văn bản nhạy cảm trước khi bị chia sẻ ra ngoài tổ chức (qua email, upload, chia sẻ file...).

Vì mục đích cuối là DLP, bộ dữ liệu cần ưu tiên:
- Văn bản có **cấu trúc và định dạng giống thật** (hợp đồng, hồ sơ, biểu mẫu, email, bảng biểu) hơn là văn bản mô tả chung chung.
- Có **các trường hợp biên (borderline)** giữa hai mức liền kề, để mô hình học được ranh giới phân loại thay vì chỉ học các mẫu "dễ".
- Đa dạng về hình thức trình bày: đoạn văn liền mạch, bảng dữ liệu, form field dạng "Trường: Giá trị", email/chat nội bộ.

---

## 2. Khung phân loại: 4 mức nhạy cảm

Áp dụng thang 4 cấp kiểu hành chính Việt Nam, được diễn giải cụ thể theo từng lĩnh vực để người gán nhãn (và mô hình) có tiêu chí rõ ràng thay vì chỉ dựa vào tên gọi mức độ.

| Cấp | Tên nhãn | Nguyên tắc chung |
|---|---|---|
| 1 | **Công khai** | Thông tin đã hoặc có thể công bố rộng rãi, không gây thiệt hại nếu bị lộ |
| 2 | **Nội bộ** | Dùng trong nội bộ tổ chức, không định danh cá nhân cụ thể, thiệt hại thấp nếu lộ ra ngoài nhưng vẫn không nên công khai |
| 3 | **Mật** | Có chứa thông tin định danh cá nhân (PII) hoặc dữ liệu nghiệp vụ cụ thể của khách hàng/nhân viên; gây thiệt hại về uy tín, tài chính hoặc vi phạm pháp luật bảo vệ dữ liệu cá nhân nếu lộ |
| 4 | **Tối mật** | Thông tin cực kỳ nhạy cảm: dữ liệu sức khỏe đặc biệt, dữ liệu sinh trắc/tài chính đầy đủ, mã xác thực, hồ sơ điều tra... gây thiệt hại nghiêm trọng hoặc vi phạm nghiêm trọng pháp luật nếu lộ |

### 2.1. Bảo hiểm (Insurance)

| Cấp | Ví dụ loại văn bản |
|---|---|
| Công khai | Điều khoản/quy tắc bảo hiểm mẫu đã công bố, bảng phí bảo hiểm niêm yết, thông cáo báo chí sản phẩm mới |
| Nội bộ | Quy trình xử lý claim nội bộ, tài liệu đào tạo đại lý, báo cáo kinh doanh tổng hợp không định danh |
| Mật | Hợp đồng bảo hiểm cá nhân (họ tên, CCCD, ngày sinh, SĐT), hồ sơ yêu cầu bồi thường có thông tin khách hàng, danh sách khách hàng kèm liên hệ |
| Tối mật | Hồ sơ bồi thường gắn với chẩn đoán/tình trạng sức khỏe chi tiết, thông tin tài chính cá nhân đầy đủ dùng để định phí, hồ sơ điều tra gian lận bảo hiểm |

### 2.2. Y tế (Healthcare)

| Cấp | Ví dụ loại văn bản |
|---|---|
| Công khai | Hướng dẫn y tế công cộng, thông báo dịch bệnh, quy định khám chữa bệnh chung, bảng giá dịch vụ công khai |
| Nội bộ | Quy trình vận hành khoa/phòng, lịch trực, biểu mẫu nội bộ chưa gắn bệnh nhân cụ thể |
| Mật | Hồ sơ bệnh án có tên bệnh nhân + chẩn đoán cơ bản, đơn thuốc có thông tin định danh, lịch hẹn khám kèm tên/SĐT |
| Tối mật | Hồ sơ bệnh án nhạy cảm (HIV, tâm thần, bệnh di truyền, sản khoa), kết quả xét nghiệm gen, hồ sơ tâm lý, thông tin liên quan pháp y |

### 2.3. Tài chính - Ngân hàng

| Cấp | Ví dụ loại văn bản |
|---|---|
| Công khai | Báo cáo tài chính thường niên đã công bố, biểu phí dịch vụ công khai, thông cáo báo chí, quy định lãi suất niêm yết |
| Nội bộ | Quy trình vận hành nội bộ, báo cáo kinh doanh tổng hợp không có thông tin khách hàng cụ thể, tài liệu đào tạo |
| Mật | Sao kê tài khoản cá nhân, thông tin khách hàng (tên, CCCD, SĐT, địa chỉ), hợp đồng tín dụng cá nhân |
| Tối mật | Số thẻ tín dụng đầy đủ kèm CVV, mã OTP/mật khẩu, hồ sơ điều tra rửa tiền/gian lận, dữ liệu xếp hạng tín dụng chi tiết kèm định danh |

### 2.4. Nhân sự (HR)

| Cấp | Ví dụ loại văn bản |
|---|---|
| Công khai | Thông báo tuyển dụng công khai, chính sách nhân sự chung đã công bố, sơ đồ tổ chức công khai |
| Nội bộ | Quy trình đánh giá nhân sự không định danh, thông báo nội bộ, chính sách lương thưởng chung |
| Mật | Hồ sơ nhân viên (CV, hợp đồng lao động, thông tin liên hệ, mức lương cụ thể), đánh giá hiệu suất cá nhân |
| Tối mật | Hồ sơ kỷ luật/khiếu nại nhạy cảm, thông tin sức khỏe nhân viên, điều tra nội bộ (quấy rối, gian lận), lương thưởng cấp điều hành kèm dữ liệu tài chính cá nhân |

> **Cần người có chuyên môn nghiệp vụ (bảo hiểm/y tế/tài chính/nhân sự) của VCI rà soát lại 16 ô định nghĩa này trước khi sinh dữ liệu hàng loạt** — đây là bước quan trọng nhất vì toàn bộ chất lượng nhãn phụ thuộc vào định nghĩa đúng ngay từ đầu.

---

## 3. Nguồn dữ liệu và tỉ lệ trộn

Theo lựa chọn kết hợp **nguồn công khai + sinh tổng hợp bằng LLM**, tỉ lệ đề xuất khác nhau theo từng cấp (vì dữ liệu "Mật"/"Tối mật" thật gần như không thể/không nên thu thập vì lý do pháp lý):

| Cấp | Nguồn công khai | Sinh tổng hợp | Ghi chú |
|---|---|---|---|
| Công khai | ~70% | ~30% | Lấy trực tiếp/paraphrase từ nguồn thật |
| Nội bộ | ~50% | ~50% | Nguồn thật ẩn danh hóa + mô phỏng thêm |
| Mật | ~20% (làm khung/định dạng) | ~80% | Dùng định dạng thật nhưng thay toàn bộ PII bằng dữ liệu giả |
| Tối mật | ~0-10% | ~90-100% | Gần như sinh hoàn toàn bằng LLM để tránh rủi ro pháp lý/đạo đức khi chạm dữ liệu thật cực nhạy cảm |

### 3.1. Gợi ý nguồn công khai theo lĩnh vực
- **Bảo hiểm:** Cổng thông tin Bộ Tài chính/Cục Quản lý, giám sát bảo hiểm; website điều khoản mẫu của các công ty bảo hiểm; Luật Kinh doanh bảo hiểm (thuvienphapluat, luatvietnam)
- **Y tế:** Cổng thông tin Bộ Y tế, tài liệu WHO Việt Nam, mẫu phiếu khám bệnh/đơn thuốc công khai, các trang phổ biến kiến thức y khoa
- **Tài chính - ngân hàng:** Báo cáo thường niên ngân hàng niêm yết (HOSE/HNX), biểu phí dịch vụ công khai trên website ngân hàng, Luật Các tổ chức tín dụng
- **Nhân sự:** Tin tuyển dụng công khai (VietnamWorks, TopCV, LinkedIn), Bộ luật Lao động, mẫu hợp đồng lao động công khai

### 3.2. Quy trình sinh dữ liệu tổng hợp bằng LLM
1. Xây dựng **prompt template** riêng cho từng ô (domain × cấp), quy định: loại văn bản cụ thể, độ dài, văn phong (trang trọng/hành chính/email/chat), định dạng trình bày (văn xuôi/bảng/form field).
2. Dùng **danh sách seed giả** (tên người, số CCCD, số tài khoản, địa chỉ...) được sinh ngẫu nhiên theo đúng format Việt Nam nhưng **không trùng và không hợp lệ về mặt checksum/thực tế**, đảm bảo không vô tình trùng với dữ liệu thật.
3. Sinh theo batch, đa dạng hóa bằng cách thay đổi: góc nhìn (báo cáo/email/biểu mẫu), độ dài, mức độ chi tiết.
4. Chèn thêm một tỷ lệ nhỏ **mẫu khó/biên** (borderline) — ví dụ văn bản Nội bộ có nhắc tên nhưng không có SĐT/CCCD — để tăng độ mạnh mẽ của mô hình.

---

## 4. Quy mô dữ liệu

- 4 lĩnh vực × 4 cấp = **16 ô**
- Mục tiêu ban đầu: **~500-1.000 mẫu/ô** → tổng khoảng **8.000 - 16.000 mẫu**
- Đề xuất bắt đầu ở mức **~800 mẫu/ô** (tổng ~12.800 mẫu) làm mốc, có thể tăng thêm sau khi đánh giá chất lượng mô hình ban đầu.
- Chia tập theo tỷ lệ **80/10/10** (train/validation/test), stratified theo từng ô để đảm bảo mỗi tập đều có đủ đại diện của cả 16 ô.

---

## 5. Schema dữ liệu (định dạng JSONL)

```json
{
  "id": "ins_conf_00123",
  "domain": "insurance | healthcare | finance_banking | hr",
  "label": "public | internal | confidential | top_secret",
  "sub_type": "hop_dong_bao_hiem_ca_nhan",
  "source_type": "public | synthetic",
  "text": "...",
  "language": "vi",
  "length_tokens": 342,
  "contains_pii": true,
  "notes": "borderline giữa nội bộ và mật do có tên nhưng không có SĐT"
}
```

---

## 6. Quy trình kiểm soát chất lượng (QC)

1. **Annotation guideline chi tiết**: tài liệu hướng dẫn gán nhãn với định nghĩa + ví dụ mẫu cho cả 16 ô (mở rộng từ mục 2), kèm các trường hợp biên điển hình.
2. **Pilot nhỏ trước khi scale**: sinh thử 20-30 mẫu/ô, người có chuyên môn rà soát trước khi sinh hàng loạt.
3. **Rà soát trùng lặp**: loại bỏ near-duplicate giữa các mẫu sinh tổng hợp.
4. **Cân bằng nhãn**: kiểm tra số lượng mẫu giữa các ô, tránh lệch phân bố.
5. **Kiểm định nhãn chéo**: nếu có từ 2 người gán nhãn trở lên, đo độ đồng thuận (inter-annotator agreement); nếu chỉ có 1 người, dùng thêm một lượt LLM-as-judge độc lập để rà soát lại nhãn.
6. **Rà soát PII giả**: đảm bảo mọi thông tin định danh trong dữ liệu synthetic đều là giả, không trùng dữ liệu thật, không vi phạm định dạng số CCCD/tài khoản thật.

---

## 7. Lưu ý pháp lý và đạo đức

- Không sử dụng dữ liệu cá nhân thật chưa được ẩn danh hóa, đặc biệt với dữ liệu "Mật" và "Tối mật".
- Tham chiếu **Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân** và **Luật An toàn thông tin mạng** khi xác định các loại thông tin thuộc diện "dữ liệu cá nhân nhạy cảm" — nên rà soát định nghĩa ở mục 2 để bám sát các văn bản này.
- Nếu sau này muốn bổ sung dữ liệu thật của tổ chức, cần có quy trình ẩn danh hóa (thay thế PII) và được phê duyệt nội bộ trước khi đưa vào bộ huấn luyện.

---

## 8. Các bước tiếp theo đề xuất

1. Duyệt và tinh chỉnh khung phân loại 16 ô ở mục 2 cùng người có chuyên môn nghiệp vụ từng lĩnh vực.
2. Soạn tài liệu annotation guideline chi tiết (mở rộng từ mục 2, thêm ví dụ đầy đủ và edge case).
3. Chạy **pilot**: sinh thử 20-30 mẫu cho một vài ô đại diện, đánh giá chất lượng và điều chỉnh prompt template.
4. Sinh dữ liệu hàng loạt theo quy mô đã thống nhất (mục 4).
5. Thực hiện QC toàn bộ (mục 6), dedup, cân bằng nhãn.
6. Chia train/val/test, đóng gói thành file JSONL cuối cùng kèm tài liệu mô tả bộ dữ liệu (datasheet).

---

*Tài liệu này là bản kế hoạch ban đầu — có thể điều chỉnh linh hoạt sau khi trao đổi thêm, đặc biệt là khung phân loại 16 ô ở mục 2.*
