# DLP Classifier

Công cụ CLI phân loại dữ liệu nhạy cảm (Data Loss Prevention) hiệu năng cao, viết bằng Go. Phát hiện PII, thông tin tài chính và dữ liệu nội bộ tổ chức theo khung 4 cấp độ bảo mật: PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED.

## Kiến trúc 2 lớp

```
                    ┌───────────────────────────────┐
   File input  ───► │  Lớp 1 — Regexing (engine Go)   │
                     │  Aho-Corasick prefilter + RE2   │
                     │  → FileConfidence (conf_regex)  │
                     └───────────┬────────────────────┘
                                 │
                    conf_regex ≥ T1 ──────► giữ nhãn engine (đa số file)
                                 │
                    conf_regex < T1
                                 ▼
                     ┌───────────────────────────────┐
                     │  Lớp 2 — LLM offline (phi4-mini) │
                     │  escalate-only + guardrail:      │
                     │  cap +1 bậc, matched_rule gate,  │
                     │  need_review → human review      │
                     └───────────┬────────────────────┘
                                 ▼
                          Nhãn cuối cùng
```

Lớp 1 tự quyết cho phần lớn file (engine tự tin, `conf_regex ≥ 0,95`). Phần còn lại (engine không chắc) được phi4-mini xem lại **chỉ để nâng mức** (không bao giờ hạ), qua một lớp guardrail chặn các trường hợp LLM nâng nhầm lên RESTRICTED thiếu bằng chứng. Chi tiết thiết kế và số liệu đánh giá nằm trong `tailieu/` (xem mục [Tài liệu & quá trình phát triển](#tài-liệu--quá-trình-phát-triển)).

`internal/agent/` đã có sẵn agent server (Unix socket + gRPC, cache engine đã compile, dispatch scan_file/scan_directory/reload_rules) nhưng **chưa được nối vào CLI** và **chưa chạy như Windows Service** — hiện tại chỉ dùng được qua CLI đồng bộ (`dlp scan`).

## Tính năng

- **Phân loại 4 cấp:** PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED
- **53 rule** phủ PII, tài chính, HR, thông tin tổ chức — cấu hình hoàn toàn bằng YAML (`rules/pii`, `rules/financial`, `rules/hr`, `rules/org`)
- **17 compound rules** nâng cấp độ khi phát hiện tổ hợp nguy hiểm (VD: PII + tài chính → RESTRICTED)
- **Lớp LLM offline (phi4-mini qua Ollama)** xem lại các file engine không chắc, escalate-only + guardrail (xem kiến trúc ở trên)
- **Xử lý song song** với worker pool (mặc định: số CPU − 1, tối đa 8)
- **Hỗ trợ 20+ định dạng file:** `.txt`, `.pdf`, `.docx`, `.xlsx`, `.csv`, `.json`, `.html`, `.eml`, `.yaml`, `.log`, `.env`, `.go`, `.java`, `.js`, `.ts`, v.v.
- **Validators tích hợp:** Luhn (thẻ tín dụng), mã tỉnh CCCD, prefix ngân hàng VN
- **Shannon entropy** phát hiện private key và dữ liệu mã hóa
- **Audit log** JSONL cho compliance

## Yêu cầu

- Go 1.21+
- (Tùy chọn, cho Lớp 2) [Ollama](https://ollama.com) chạy local với model `phi4-mini` nếu muốn dùng pipeline có LLM offline

## Cài đặt

```bash
git clone https://github.com/ngocphamminh0401-hub/dlp-data-classifier-cli.git
cd dlp-data-classifier-cli
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

Việc đánh giá hiện dùng bộ script `scripts/pha2_collect.go` (quét toàn corpus, xuất feature) +
`scripts/pha2_split.go` (chia train/validation/holdout 70/15/15) + các notebook Python trong
`scripts/notebooks/` (fit FileConfidence, đánh giá pipeline). Toàn bộ quá trình và quyết định
kỹ thuật được ghi lại theo từng "Pha" trong `tailieu/`.

### Kết quả mới nhất (holdout 3.781 file, ground-truth từ tên thư mục dataset synthetic)

| | accuracy | over-classification | under-classification (rò rỉ) |
|---|---|---|---|
| Engine đứng một mình (chỉ Lớp 1, không có LLM) | 84,7% | 8,9% | 6,4% |
| **Pipeline sản xuất (Lớp 1 + Lớp 2 LLM + guardrail)** | **80,4%** | **15,7%** | **3,9%** |

Pipeline đánh đổi ~4 điểm accuracy và tăng over-classification để giảm rò rỉ (under) từ 6,4%
xuống 3,9% — coi là đánh đổi hợp lý cho bài toán DLP (hậu quả rò rỉ nghiêm trọng hơn gắn nhầm mức
cao). Chi tiết đầy đủ theo từng lớp, breakdown theo mức phân loại, và các phương án đã thử nhưng
KHÔNG dùng (kèm lý do) nằm trong `tailieu/pha15-guardrail-lop2.md` và `tailieu/pha20-cong-thuc-tin-cay-lop-llm.md`.

⚠️ Corpus đánh giá hiện là **100% dữ liệu synthetic** — con số tuyệt đối trên dữ liệu thật có thể
khác (xem giới hạn ghi trong từng báo cáo Pha).

## Cấu trúc Rules

Rules được định nghĩa bằng YAML trong thư mục `rules/`:

```
rules/
├── pii/             # Thông tin cá nhân (10 rule)
│   ├── vn_id.yaml       # CCCD / CMND
│   ├── vn_name.yaml     # Họ tên
│   ├── passport.yaml    # Hộ chiếu
│   ├── phone.yaml       # Số điện thoại
│   ├── email.yaml       # Email
│   ├── dob.yaml         # Ngày sinh
│   ├── health.yaml      # Dữ liệu y tế
│   ├── social_insurance.yaml
│   ├── biometric.yaml   # Sinh trắc học
│   ├── ethnicity_religion_political.yaml
│   └── location_tracking.yaml
├── financial/       # Thông tin tài chính (20 rule)
│   ├── credit_card.yaml # Thẻ tín dụng (Luhn validator)
│   ├── cvv.yaml
│   ├── bank_account.yaml
│   ├── iban.yaml
│   ├── swift_bic.yaml
│   ├── tax_code.yaml
│   ├── otp_auth.yaml
│   └── ...
├── hr/              # Nhân sự (7 rule)
│   ├── offer_letter.yaml
│   ├── disciplinary_health_investigation.yaml
│   ├── sexual_harassment_complaint.yaml
│   └── ...
├── org/             # Thông tin tổ chức (14 rule)
│   ├── credentials.yaml # API key, password, token
│   ├── classified_doc.yaml
│   ├── contract.yaml
│   ├── internal_ip.yaml
│   └── ...
└── rules.yaml       # Compound rules (17 tổ hợp)
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

## Kiến trúc Lớp 1 (Regexing engine)

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
    ▼ FileConfidence                   điểm tin cậy — quyết định có cần Lớp 2 không
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

## Tài liệu & quá trình phát triển

Toàn bộ quyết định kỹ thuật (công thức FileConfidence, ngưỡng routing, guardrail LLM, các
phương án đã thử nhưng bị loại kèm lý do) được ghi lại tuần tự theo từng "Pha" trong `tailieu/`.
Đáng chú ý:

- `tailieu/cong-thuc-tinh-diem-file-confidence.md` — công thức FileConfidence (Lớp 1) hiện dùng.
- `tailieu/pha15-guardrail-lop2.md` — guardrail Lớp 2 đang chạy production (Policy C).
- `tailieu/pha20-cong-thuc-tin-cay-lop-llm.md` — thử nghiệm công thức tin cậy riêng cho nhãn LLM
  (`conf_llm`), kèm lý do vì sao chưa đưa vào production.
