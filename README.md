# DLP Classifier

Công cụ CLI phân loại dữ liệu nhạy cảm (Data Loss Prevention) hiệu năng cao, viết bằng Go. Phát hiện PII, thông tin tài chính và dữ liệu nội bộ tổ chức theo khung 4 cấp độ bảo mật của VNPT.

## Tính năng

- **Phân loại 4 cấp:** PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED
- **25 rules** phủ PII, tài chính, thông tin tổ chức — cấu hình hoàn toàn bằng YAML
- **14 compound rules** nâng cấp độ khi phát hiện tổ hợp nguy hiểm (VD: PII + tài chính → RESTRICTED)
- **Xử lý song song** với worker pool (mặc định: số CPU − 1, tối đa 8)
- **Hỗ trợ 20+ định dạng file:** `.txt`, `.pdf`, `.docx`, `.xlsx`, `.csv`, `.json`, `.html`, `.eml`, `.yaml`, `.log`, `.env`, `.go`, `.java`, `.js`, `.ts`, v.v.
- **Throughput ~15.000 file/s** trên dataset 17.000 file
- **Validators tích hợp:** Luhn (thẻ tín dụng), mã tỉnh CCCD, prefix ngân hàng VN
- **Shannon entropy** phát hiện private key và dữ liệu mã hóa
- **Audit log** JSONL cho compliance

## Yêu cầu

- Go 1.21+

## Cài đặt

```bash
git clone https://github.com/vnpt/dlp-classifier
cd dlp-classifier
go build -o dlp.exe ./cmd/dlp
```

## Sử dụng nhanh

### Quét file hoặc thư mục

```bash
# Quét 1 file, in kết quả dạng text
./dlp.exe scan --path "D:/data/hop_dong.pdf" --output text

# Quét thư mục đệ quy
./dlp.exe scan --path "D:/data" --output text

# Xuất JSON
./dlp.exe scan --path "D:/data" --output json --output-file findings.json

# Xuất CSV, chỉ lấy từ CONFIDENTIAL trở lên
./dlp.exe scan --path "D:/data" --output csv --output-file findings.csv --level-filter CONFIDENTIAL

# Ghi audit log riêng (JSONL)
./dlp.exe scan --path "D:/data" --output json --audit-log audit.jsonl
```

### Các flag chính

| Flag | Mô tả | Mặc định |
|---|---|---|
| `--path` | File hoặc thư mục cần quét *(bắt buộc)* | — |
| `--output` | Định dạng output: `text` / `json` / `csv` | `json` |
| `--output-file` | Ghi kết quả ra file | stdout |
| `--level-filter` | Chỉ hiện từ level: `PUBLIC` / `INTERNAL` / `CONFIDENTIAL` / `RESTRICTED` | `PUBLIC` |
| `--min-confidence` | Ngưỡng confidence tối thiểu (0.0–1.0) | `0.60` |
| `--workers` | Số goroutine xử lý song song | CPU count − 1 |
| `--max-file-size` | Bỏ qua file lớn hơn ngưỡng này, VD: `50MB` | `50MB` |
| `--audit-log` | Đường dẫn file audit log JSONL | — |
| `--dry-run` | Liệt kê file sẽ quét, không chạy thật | `false` |
| `--rules` | Thư mục chứa rules YAML | `./rules` |

### Benchmark throughput

```bash
./dlp.exe benchmark --path "D:/data" --iterations 3
```

### Kiểm tra rules

```bash
./dlp.exe validate-rules
```

## Đánh giá độ chính xác

### Chuẩn bị dataset

Tổ chức file test theo cấu trúc thư mục với tên nhãn:

```
dataset/
├── L1/             # hoặc L1_PUBLIC
├── L2/             # hoặc L2_INTERNAL
├── L3/             # hoặc L3_CONFIDENTIAL
├── L4/             # hoặc L4_RESTRICTED
└── edge/           # edge cases — không tính điểm
```

### Chạy đánh giá

```bash
# Báo cáo đầy đủ (accuracy, F1, confusion matrix)
go run scripts/eval_dataset.go --dataset "D:/testdlp/dlp_testdata"

# Chỉ xem file phân loại sai
go run scripts/eval_dataset.go --dataset "D:/testdlp/dlp_testdata" --wrong-only

# Bao gồm edge cases
go run scripts/eval_dataset.go --dataset "D:/testdlp/dlp_testdata" --edge

# Xuất kết quả chi tiết ra CSV
go run scripts/eval_dataset.go --dataset "D:/testdlp/dlp_testdata" --out-csv results.csv
```

### Kết quả hiện tại (17.000 file)

| Class | Samples | Precision | Recall | F1 |
|---|---|---|---|---|
| PUBLIC | 2.250 | 79.0% | 91.6% | 84.8% |
| INTERNAL | 4.400 | 42.5% | 63.7% | 51.0% |
| CONFIDENTIAL | 6.100 | 62.1% | 43.4% | 51.1% |
| RESTRICTED | 4.250 | 100.0% | 83.2% | 90.8% |

**Accuracy: 64.96% — Macro F1: 69.42% — Throughput: ~15.000 files/s**

## Cấu trúc Rules

Rules được định nghĩa bằng YAML trong thư mục `rules/`:

```
rules/
├── pii/             # Thông tin cá nhân
│   ├── vn_id.yaml       # CCCD / CMND
│   ├── passport.yaml    # Hộ chiếu
│   ├── phone.yaml       # Số điện thoại
│   ├── email.yaml       # Email
│   ├── dob.yaml         # Ngày sinh
│   ├── health.yaml      # Dữ liệu y tế
│   ├── social_insurance.yaml
│   └── biometric.yaml   # Sinh trắc học
├── financial/       # Thông tin tài chính
│   ├── credit_card.yaml # Thẻ tín dụng (Luhn validator)
│   ├── cvv.yaml
│   ├── bank_account.yaml
│   ├── iban.yaml
│   ├── swift_bic.yaml
│   ├── tax_code.yaml
│   └── income.yaml
├── org/             # Thông tin tổ chức
│   ├── credentials.yaml # API key, password, token
│   ├── classified_doc.yaml
│   ├── contract.yaml
│   ├── internal_ip.yaml
│   └── ...
└── rules.yaml       # Compound rules
```

### Cấu trúc một rule

```yaml
id: credit_card_001
name: Thẻ tín dụng / ghi nợ quốc tế
category: financial
level: SECRET
priority: 100
weight: 1.0

keywords:
  primary: [visa, mastercard, thẻ tín dụng]
  secondary: [số thẻ, card number]

patterns:
  - regex: '\b4[0-9]{12}(?:[0-9]{3})?\b'
    description: Visa card
    confidence: 0.85
    validators: [luhn]

fp_reduction:
  cvv_expiry_boost: 0.10
```

### Compound rules

Khai báo trong `rules/rules.yaml` — kích hoạt khi nhiều loại dữ liệu nhạy cảm cùng xuất hiện:

```yaml
compound_rules:
  - name: PII + Financial → RESTRICTED
    conditions: [pii, financial]
    min_component_level: CONFIDENTIAL
    result_level: RESTRICTED
    violation_type: PCI_DSS_3.3.1
    alert_priority: CRITICAL
```

## Kiến trúc

```
Input file
    │
    ▼ Aho-Corasick keyword pre-scan   O(n+m) — lọc chunk không có keyword
    │
    ▼ RE2 Regex matching               O(n) worst-case, không có ReDoS
    │
    ▼ Distance-weighted context score  keyword gần → boost cao hơn
    │
    ▼ Domain validators                Luhn, CCCD prefix, bank prefix
    │
    ▼ Shannon entropy check            phát hiện key mã hóa, private key
    │
    ▼ Compound rules                   nâng cấp theo tổ hợp nguy hiểm
    │
    ▼ Kết quả phân loại
```

**Thread safety:** Engine là read-only sau khi khởi tạo — nhiều goroutine worker dùng chung không cần lock.

## Cấu hình

Tạo file `~/.dlp/config.yaml`:

```yaml
rules:
  dir: ./rules
  min_confidence: 0.60

scanner:
  workers: 4
  max_file_size: 50MB

output:
  default_format: json
  audit_log: /var/log/dlp/audit.jsonl
```

## Output Format

### Text
```
[OK/CONFIDENTIAL] D:/data/hop_dong.pdf
  matches: 3  duration: 5ms
  - contract_001 conf=0.82 offset=1024 len=12
  - email_001    conf=0.91 offset=2048 len=25

Summary
  PUBLIC:       0
  INTERNAL:     0
  CONFIDENTIAL: 1
  RESTRICTED:   0
  Thời gian:    6ms
```

### JSON (JSONL — 1 object/dòng)
```json
{"path":"D:/data/hop_dong.pdf","status_code":1,"level_code":2,"level":"CONFIDENTIAL","scan_duration_ms":5000000,"matches":[{"rule_id":"contract_001","confidence":0.82,"offset":1024}]}
```

### CSV
```
path,status,level,rule_id,offset,length,confidence,error
D:/data/hop_dong.pdf,OK,CONFIDENTIAL,contract_001,1024,12,0.8200,
```
