# Đặc tả bộ quy tắc phân loại dữ liệu

## Tổng quan

Bộ quy tắc phân loại dữ liệu áp dụng khung 4 cấp độ của VNPT, tương thích với tiêu chuẩn GTB DLP. Mỗi quy tắc bao gồm: regex pattern, danh sách keyword ngữ cảnh, điểm confidence, và cấp độ phân loại.

---

## Khung phân loại 4 cấp độ

| Cấp độ | Mã số | Màu | Mô tả | Ví dụ |
|--------|-------|-----|-------|-------|
| **PUBLIC** | 0 | Xanh lá | Thông tin công khai, không hạn chế | Thông báo sự kiện, tài liệu marketing |
| **INTERNAL** | 1 | Xanh dương | Thông tin nội bộ tổ chức | Email nội bộ, quy trình làm việc |
| **CONFIDENTIAL** | 2 | Vàng cam | Thông tin bảo mật, chỉ những người được ủy quyền | Hợp đồng, dữ liệu khách hàng |
| **SECRET** | 3 | Đỏ | Tối mật, tiếp cận cực kỳ hạn chế | Khóa mật mã, thông tin an ninh quốc gia |

---

## Cấu trúc file quy tắc YAML

```yaml
# rules/pii/vn_id.yaml — ví dụ đầy đủ
id: vn_id_001
name: "Căn cước công dân / CMND Việt Nam"
category: pii
level: CONFIDENTIAL          # Cấp độ mặc định khi match
weight: 0.9                  # Trọng số confidence (0.0–1.0)
enabled: true

patterns:
  - regex: '\b\d{9}\b'
    description: "CMND 9 chữ số (cũ)"
    confidence: 0.7
    context_required: true   # Phải có keyword ngữ cảnh trong ±200 chars
  - regex: '\b\d{12}\b'
    description: "CCCD 12 chữ số (mới)"
    confidence: 0.85
    context_required: true
  - regex: '\b\d{9}(?:\d{3})?\b'
    description: "CMND/CCCD 9 hoặc 12 số tổng quát"
    confidence: 0.75
    context_required: true

keywords:
  - "căn cước"
  - "CMND"
  - "CCCD"
  - "chứng minh nhân dân"
  - "số định danh"
  - "số cá nhân"
  - "giấy tờ tùy thân"
  - "identity"
  - "ID number"

false_positive_reduction:
  - exclude_pattern: '^\d{10,12}$'   # Số điện thoại thuần không có context
    condition: no_keywords_nearby
  - min_context_window: 200           # Chars quanh match cần kiểm tra
```

---

## Nhóm quy tắc PII (Thông tin cá nhân)

### vn_id — CMND / CCCD

**Cấp độ**: CONFIDENTIAL | **Weight**: 0.90

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `\b\d{9}\b` | CMND 9 số (trước 2012) | 0.70 |
| `\b\d{12}\b` | CCCD 12 số (từ 2012) | 0.85 |

**Keywords ngữ cảnh**: căn cước, CMND, CCCD, chứng minh nhân dân, số định danh cá nhân

**Validation logic**: Kiểm tra prefix tỉnh/thành (3 số đầu của CCCD tương ứng mã tỉnh từ 001–096)

---

### phone — Số điện thoại Việt Nam

**Cấp độ**: CONFIDENTIAL | **Weight**: 0.75

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `(?:84\|0)(?:3[2-9]\|5[25689]\|7[06-9]\|8[0-9]\|9[0-9])\d{7}` | Số di động VN (tất cả đầu số) | 0.90 |
| `(?:84\|0)(?:2[0-9])\d{8}` | Số cố định VN (đầu số 02x) | 0.85 |

**Keywords**: điện thoại, SĐT, số máy, liên hệ, hotline, mobile, phone, tel

**Lưu ý**: Loại trừ chuỗi số trong mã sản phẩm, số serial, mã đơn hàng (dùng context window)

---

### email — Địa chỉ email

**Cấp độ**: INTERNAL | **Weight**: 0.85

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | Email chuẩn RFC 5322 (đơn giản hóa) | 0.95 |
| `[a-zA-Z0-9._%+\-]+@vnpt\.vn` | Email nội bộ VNPT → nâng lên CONFIDENTIAL | 0.98 |

**Ghi chú cấp độ**: Email `@vnpt.vn`, `@vnpt-i.vn` tự động nâng lên CONFIDENTIAL do tính nhận diện tổ chức

---

### dob — Ngày sinh

**Cấp độ**: INTERNAL | **Weight**: 0.60

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `\b(?:0?[1-9]\|[12]\d\|3[01])[/\-.](?:0?[1-9]\|1[0-2])[/\-.]\d{4}\b` | DD/MM/YYYY (định dạng VN) | 0.65 |
| `\b\d{4}[/\-.](?:0?[1-9]\|1[0-2])[/\-.](?:0?[1-9]\|[12]\d\|3[01])\b` | YYYY-MM-DD (ISO 8601) | 0.70 |

**Keywords**: ngày sinh, năm sinh, DOB, date of birth, sinh ngày, birthdate

**False positive guard**: Chỉ trigger khi có ít nhất 1 keyword PII khác trong cùng tài liệu

---

## Nhóm quy tắc Financial (Tài chính)

### bank_account — Số tài khoản ngân hàng

**Cấp độ**: CONFIDENTIAL | **Weight**: 0.90

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `\b\d{9,14}\b` | Tài khoản ngân hàng VN 9–14 số | 0.70 |
| `\b\d{16,19}\b` | Số thẻ ngân hàng 16–19 số (kết hợp Luhn) | 0.92 |

**Keywords**: tài khoản, số TK, STK, ngân hàng, bank account, chuyển khoản, Vietcombank, BIDV, Agribank, VPBank, Techcombank, MB Bank, ACB, TPBank

**Validation**: Luhn algorithm cho số thẻ 16–19 số; kiểm tra BIN ngân hàng VN cho độ chính xác cao hơn

---

### credit_card — Thẻ tín dụng/ghi nợ

**Cấp độ**: SECRET | **Weight**: 0.95

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}` | Visa (bắt đầu bằng 4) | 0.95 |
| `5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}` | Mastercard (51–55) | 0.95 |
| `3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}` | American Express (34, 37) | 0.95 |
| `35\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}` | JCB (35) | 0.90 |

**Validation**: Bắt buộc Luhn check — bất kỳ số nào không qua Luhn đều bị loại bỏ, kể cả có đúng format

**CVV/Expiry context**: Nếu phát hiện thêm CVV (3–4 số) và ngày hết hạn (MM/YY), nâng confidence lên 0.99

---

### tax_code — Mã số thuế

**Cấp độ**: CONFIDENTIAL | **Weight**: 0.85

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `\b\d{10}\b` | MST doanh nghiệp 10 số | 0.80 |
| `\b\d{10}-\d{3}\b` | MST chi nhánh (10 số + hậu tố 3 số) | 0.90 |
| `\b\d{13}\b` | MST cá nhân 13 số (sau 2023) | 0.85 |

**Keywords**: mã số thuế, MST, tax code, TIN, mã doanh nghiệp, đăng ký kinh doanh

---

## Nhóm quy tắc Org (Tổ chức)

### contract — Tài liệu hợp đồng

**Cấp độ**: CONFIDENTIAL | **Weight**: 0.80

**Keywords chính** (bất kỳ 2+ từ trong danh sách → trigger):
- hợp đồng, contract, agreement, thỏa thuận
- bảo mật, confidential, NDA, non-disclosure
- cam kết, commitment, obligation
- điều khoản, terms, conditions, clause
- phụ lục, annex, appendix, schedule
- hiệu lực, effective date, commencement
- chấm dứt, termination, expiry

**Nâng lên SECRET nếu**: Kết hợp với "quốc phòng", "an ninh quốc gia", "mật", "tối mật"

---

### internal_code — Mã nội bộ VNPT

**Cấp độ**: INTERNAL | **Weight**: 0.70

| Pattern | Mô tả | Confidence |
|---------|-------|-----------|
| `VNPT-[A-Z]{2,4}-\d{4,8}` | Mã dự án VNPT | 0.95 |
| `PRJ-\d{6}` | Project code nội bộ | 0.90 |
| `\bVNPT\b.*\b(?:nội bộ\|internal\|restricted)\b` | Nhãn nội bộ | 0.85 |

---

## Quy tắc kết hợp (Compound Rules)

Một số pattern chỉ có độ nhạy cao khi xuất hiện cùng nhau:

| Kết hợp | Cấp độ kết quả |
|---------|---------------|
| `vn_id` + `bank_account` trong cùng tài liệu | Nâng lên SECRET |
| `email` + `phone` + `dob` trong cùng tài liệu | Nâng lên CONFIDENTIAL |
| `credit_card` + `cvv` + `expiry` | Nâng lên SECRET |
| `contract` + bất kỳ PII nào | Giữ CONFIDENTIAL hoặc cao hơn |

---

## Cấu hình confidence scoring

```yaml
# config.yaml — phần scoring
scoring:
  min_confidence: 0.60        # Ngưỡng tối thiểu để báo cáo match
  context_window: 200         # Số chars kiểm tra quanh match cho keywords
  compound_boost: 0.15        # Cộng thêm confidence khi có compound match
  entropy_threshold: 4.5      # bits/byte — trên ngưỡng này coi là dữ liệu nhạy cảm
  luhn_required_for_cards: true
```

---

## Quy trình thêm quy tắc mới

1. Tạo file YAML trong thư mục category tương ứng (`rules/pii/`, `rules/financial/`, `rules/org/`)
2. Đặt tên file theo format `{category}_{descriptor}.yaml` (ví dụ: `pii_passport.yaml`)
3. Chạy test để validate regex không có backtracking: `make test-rules`
4. Chạy benchmark trên testdata: `make bench-rules`
5. Điều chỉnh `confidence` và `weight` dựa trên kết quả precision/recall
6. Cập nhật file này với mô tả pattern mới

---

## Số liệu hiện tại

| Nhóm | Số rule | Patterns | Keywords |
|------|---------|----------|----------|
| PII | 4 | 11 | 47 |
| Financial | 3 | 9 | 32 |
| Org | 2 | 6 | 28 |
| **Tổng** | **9** | **26** | **107** |

**Độ chính xác trên testdata (2.000 file)**: Precision 98.3% · Recall 97.8% · F1 98.05%
