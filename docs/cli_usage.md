# Hướng dẫn sử dụng CLI

## Cài đặt

### Yêu cầu hệ thống
- Go 1.22 trở lên
- Linux / macOS / Windows (WSL2)
- RAM tối thiểu 256 MB

### Build từ source

```bash
git clone https://github.com/vnpt/dlp-classifier.git
cd dlp-classifier
make build
# Binary được tạo tại: ./bin/dlp
```

### Cài đặt toàn cục

```bash
make install
# Hoặc thủ công:
cp bin/dlp /usr/local/bin/dlp
```

### Verify

```bash
dlp version
# dlp-classifier v1.0.0 (go1.22, linux/amd64)
```

---

## Cú pháp cơ bản

```
dlp <command> [flags] [arguments]
```

### Các lệnh chính

| Lệnh | Mô tả |
|------|-------|
| `scan` | Quét file hoặc thư mục |
| `serve` | Khởi động agent server (Unix socket / gRPC) |
| `rules` | Quản lý và kiểm tra bộ quy tắc |
| `version` | Hiển thị phiên bản |
| `help` | Hiển thị trợ giúp |

---

## Lệnh `scan`

### Cú pháp

```
dlp scan [flags] <path>
```

### Flags

| Flag | Kiểu | Mặc định | Mô tả |
|------|------|---------|-------|
| `--format` | string | `stdout` | Định dạng output: `stdout`, `csv`, `json` |
| `--output` | string | - | Ghi kết quả ra file (không có = in ra terminal) |
| `--workers` | int | `GOMAXPROCS×4` | Số goroutine worker |
| `--max-size` | string | `50MB` | Kích thước file tối đa (VD: `10MB`, `1GB`) |
| `--min-confidence` | float | `0.60` | Ngưỡng confidence tối thiểu (0.0–1.0) |
| `--level` | string | `INTERNAL` | Chỉ báo cáo từ cấp này trở lên: `INTERNAL`, `CONFIDENTIAL`, `SECRET` |
| `--rules-dir` | string | `./rules` | Đường dẫn tới thư mục chứa rule YAML |
| `--audit-log` | string | - | Ghi audit log JSONL vào file |
| `--no-recurse` | bool | false | Không duyệt đệ quy thư mục con |
| `--skip` | string | - | Glob pattern bỏ qua (VD: `"*.log,*.tmp"`) |
| `--timeout` | duration | `0` | Timeout toàn bộ lần scan (0 = không giới hạn) |

### Ví dụ sử dụng

#### Quét một file

```bash
dlp scan /data/contracts/hdlv_2025.docx
```

Output mẫu:
```
[CONFIDENTIAL] /data/contracts/hdlv_2025.docx
  ├─ Rule: vn_id_001        Match: "034012345678"  Offset: 1423  Confidence: 0.92
  ├─ Rule: phone_001        Match: "0912345678"     Offset: 1891  Confidence: 0.91
  └─ Rule: contract_kw_001  Match: "bảo mật"        Offset: 892   Confidence: 0.85

Exit code: 2
```

#### Quét toàn bộ thư mục, xuất JSON

```bash
dlp scan --format json --output results.json /data/documents/
```

#### Quét với ngưỡng confidence cao, chỉ SECRET

```bash
dlp scan --level SECRET --min-confidence 0.90 /data/
```

#### Quét qua stdin (pipe)

```bash
cat document.txt | dlp scan --format json -
```

#### Quét với audit log

```bash
dlp scan \
  --format csv \
  --output report.csv \
  --audit-log /var/log/dlp/audit.jsonl \
  /data/
```

#### Tùy chỉnh số worker (giảm CPU usage)

```bash
dlp scan --workers 4 --format stdout /data/
```

---

## Lệnh `serve`

Khởi động agent server nhận scan request qua Unix socket hoặc gRPC.

### Cú pháp

```
dlp serve [flags]
```

### Flags

| Flag | Kiểu | Mặc định | Mô tả |
|------|------|---------|-------|
| `--mode` | string | `unix` | Chế độ: `unix` hoặc `grpc` |
| `--socket` | string | `/tmp/dlp.sock` | Đường dẫn Unix socket |
| `--grpc-addr` | string | `:50051` | Địa chỉ gRPC server |
| `--tls-cert` | string | - | Đường dẫn TLS certificate (gRPC) |
| `--tls-key` | string | - | Đường dẫn TLS private key (gRPC) |

### Ví dụ

```bash
# Khởi động Unix socket server
dlp serve --mode unix --socket /tmp/dlp-agent.sock

# Khởi động gRPC server với TLS
dlp serve --mode grpc \
  --grpc-addr :50051 \
  --tls-cert /etc/dlp/server.crt \
  --tls-key /etc/dlp/server.key
```

### Gửi request tới Unix socket

```bash
echo '{"action":"scan","path":"/data/file.txt","options":{"format":"json"}}' \
  | nc -U /tmp/dlp-agent.sock
```

---

## Lệnh `rules`

### Sub-commands

```bash
# Liệt kê tất cả rules đã load
dlp rules list

# Kiểm tra syntax rule YAML
dlp rules validate ./rules/pii/vn_id.yaml

# Test rule trên chuỗi văn bản
dlp rules test --rule vn_id_001 --text "Số CCCD: 034012345678"

# Test rule trên file
dlp rules test --rule credit_card_001 --file /data/test.txt

# Benchmark toàn bộ rules trên testdata
dlp rules bench --testdata ./testdata/
```

---

## Định dạng output

### stdout (mặc định)

```
[LEVEL] <file_path>
  ├─ Rule: <rule_id>  Match: "<matched_text>"  Offset: <byte_offset>  Confidence: <score>
  └─ ...

Summary: <N> files scanned · <M> sensitive files found · <duration>
```

### CSV

```csv
path,level,rule_id,rule_name,match_preview,offset,confidence,timestamp
/data/file.docx,CONFIDENTIAL,vn_id_001,CMND/CCCD,"034012...",1423,0.92,2025-01-15T08:30:00Z
```

### JSON

```json
[
  {
    "path": "/data/file.docx",
    "level": "CONFIDENTIAL",
    "level_code": 2,
    "scan_duration_ms": 45,
    "matches": [
      {
        "rule_id": "vn_id_001",
        "rule_name": "Căn cước công dân / CMND",
        "category": "pii",
        "match_preview": "034012...",
        "offset": 1423,
        "length": 12,
        "confidence": 0.92,
        "context": "...số CCCD: 034012345678 ngày cấp..."
      }
    ]
  }
]
```

### JSONL Audit Log

```jsonl
{"ts":"2025-01-15T08:30:01Z","path":"/data/file.docx","level":"CONFIDENTIAL","rule":"vn_id_001","offset":1423,"confidence":0.92,"worker_id":3}
{"ts":"2025-01-15T08:30:01Z","path":"/data/report.xlsx","level":"INTERNAL","rule":"email_001","offset":567,"confidence":0.95,"worker_id":1}
```

---

## Exit codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Quét thành công, không tìm thấy dữ liệu nhạy cảm (PUBLIC) |
| `1` | Tìm thấy dữ liệu INTERNAL |
| `2` | Tìm thấy dữ liệu CONFIDENTIAL |
| `3` | Tìm thấy dữ liệu SECRET |
| `10` | Lỗi: không tìm thấy file/thư mục |
| `11` | Lỗi: không đọc được file (permission denied) |
| `12` | Lỗi: rules directory không hợp lệ |
| `99` | Lỗi nội bộ không xác định |

Sử dụng exit code trong script:
```bash
dlp scan /data/
RESULT=$?
if [ $RESULT -ge 2 ]; then
    echo "CẢNH BÁO: Phát hiện dữ liệu CONFIDENTIAL/SECRET!"
    exit 1
fi
```

---

## Cấu hình qua file

Tạo `config.yaml` trong thư mục chạy hoặc chỉ định bằng `--config`:

```yaml
# config.yaml
scanner:
  workers: 16
  max_file_size: "50MB"
  batch_size: 2_000_000
  mmap_threshold: "1MB"   # File lớn hơn này sẽ dùng mmap

rules:
  dir: "./rules"
  min_confidence: 0.60
  context_window: 200

output:
  default_format: "json"
  audit_log: "/var/log/dlp/audit.jsonl"
  audit_rotation_size: "100MB"
  audit_rotation_interval: "24h"

agent:
  socket_path: "/tmp/dlp.sock"
  grpc_addr: ":50051"
```

```bash
dlp scan --config /etc/dlp/config.yaml /data/
```

---

## Tích hợp với CI/CD

### GitHub Actions

```yaml
- name: DLP Scan
  run: |
    dlp scan --format json --output dlp-report.json \
      --level CONFIDENTIAL ./src/
    if [ $? -ge 2 ]; then
      echo "::error::Phát hiện dữ liệu nhạy cảm trong source code!"
      cat dlp-report.json
      exit 1
    fi
```

### Jenkins Pipeline

```groovy
stage('DLP Scan') {
    steps {
        sh 'dlp scan --format csv --output dlp-report.csv --level INTERNAL .'
        publishHTML([allowMissing: false, reportDir: '.', reportFiles: 'dlp-report.csv'])
    }
}
```

---

## Troubleshooting

### Quét chậm

```bash
# Kiểm tra số worker đang dùng
dlp scan --workers $(nproc) /data/

# Bỏ qua file lớn không cần thiết
dlp scan --max-size 10MB --skip "*.iso,*.zip,*.tar.gz" /data/
```

### False positive nhiều

```bash
# Tăng ngưỡng confidence
dlp scan --min-confidence 0.85 /data/

# Kiểm tra rule nào đang trigger nhiều nhất
dlp scan --format json /data/ | jq '.[] | .matches[].rule_id' | sort | uniq -c | sort -rn
```

### Out of memory

```bash
# Giảm số worker và giới hạn kích thước file
dlp scan --workers 2 --max-size 5MB /data/

# Kiểm tra current RAM usage
/usr/bin/time -v dlp scan /data/ 2>&1 | grep "Maximum resident"
```
