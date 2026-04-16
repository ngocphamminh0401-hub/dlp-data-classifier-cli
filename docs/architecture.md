# Kiến trúc hệ thống DLP Classifier

## Tổng quan

DLP Classifier là một công cụ dòng lệnh (CLI) viết bằng Go 1.22, có khả năng quét và phân loại dữ liệu nhạy cảm trên 2 triệu file với độ chính xác ≥ 98%, tiêu thụ CPU < 2% mỗi nhân và RAM < 200 MB working set.

---

## Sơ đồ kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                         Input Layer                             │
│          File path / directory / stdin / Agent JSON request     │
└────────────┬───────────────────┬───────────────────────────────┘
             │                   │                        │
     ┌───────▼──────┐   ┌────────▼────────┐   ┌──────────▼──────────┐
     │  File Walker │   │   Rule Engine   │   │  Content Extractor  │
     │  goroutine   │   │ Regex+Keywords  │   │  txt/docx/pdf/xlsx  │
     │  pool, 2M/b  │   │ Confidence score│   │  eml/html stream    │
     └───────┬──────┘   └────────┬────────┘   └──────────┬──────────┘
             │                   │                        │
             └───────────────────▼────────────────────────┘
                        ┌────────────────────┐
                        │   Scanner Core     │
                        │     Go binary      │
                        │  Aho-Corasick      │
                        │  RE2 regex engine  │
                        │  Shannon Entropy   │
                        │  Worker pool       │
                        │  mmap read         │
                        │  result aggregator │
                        └────────┬───────────┘
               ┌─────────────────┼──────────────────┐
       ┌───────▼──────┐  ┌───────▼───────┐  ┌───────▼──────┐
       │Agent Protocol│  │  CLI Output   │  │  Audit Log   │
       │ Unix socket  │  │stdout/CSV/JSON│  │ matched rule │
       │ gRPC         │  │exit code/lvl  │  │ JSONL append │
       └──────────────┘  └───────────────┘  └──────────────┘
```

---

## Các thành phần chính

### 1. Input Layer (`cmd/dlp/main.go`)

Điểm vào duy nhất của hệ thống. Nhận input từ:

- **File path / directory**: Đường dẫn tuyệt đối hoặc tương đối tới file/thư mục cần quét
- **stdin**: Dữ liệu truyền qua pipe (`cat file.txt | dlp scan`)
- **Agent JSON request**: Payload JSON từ agent qua Unix socket hoặc gRPC

Trả về **exit code** theo cấp độ phân loại:
| Exit code | Cấp độ | Ý nghĩa |
|-----------|--------|---------|
| 0 | PUBLIC | Không tìm thấy dữ liệu nhạy cảm |
| 1 | INTERNAL | Dữ liệu nội bộ tổ chức |
| 2 | CONFIDENTIAL | Dữ liệu bảo mật |
| 3 | SECRET | Dữ liệu tối mật |

---

### 2. File Walker (`internal/walker/`)

Chịu trách nhiệm duyệt hệ thống file song song:

- **Goroutine pool**: Sử dụng `golang.org/x/sync/errgroup` với bounded goroutines, mặc định `GOMAXPROCS × 4`
- **Batch processing**: Xử lý theo lô 2 triệu file, dùng channel có buffer để tránh OOM
- **Filter**: Bỏ qua file theo extension, kích thước tối đa (mặc định 50 MB), symlink loop detection

```go
// Ví dụ cấu hình Walker
walker.Config{
    MaxWorkers:  runtime.GOMAXPROCS(0) * 4,
    MaxFileSize: 50 * 1024 * 1024, // 50 MB
    BatchSize:   2_000_000,
    SkipDirs:    []string{".git", "node_modules", "__pycache__"},
}
```

---

### 3. Rule Engine (`internal/engine/`)

Ba thuật toán phối hợp để đạt độ chính xác cao:

#### Aho-Corasick (`aho_corasick.go`)
- Xây dựng trie từ toàn bộ keyword trong `rules/*.yaml` một lần lúc khởi động
- Multi-pattern matching O(n + m) với n = độ dài text, m = số lần match
- Thư viện: `github.com/BobuSumisu/aho-corasick`

#### RE2 Regex Engine (`regex.go`)
- Sử dụng `regexp` chuẩn của Go (RE2-compatible, không có backtracking catastrophic)
- Mỗi pattern được pre-compile thành `*regexp.Regexp` khi load rules
- Confidence scoring: mỗi match trả về score 0.0–1.0 dựa trên độ dài match, context, và checksum validation (Luhn cho thẻ tín dụng, v.v.)

#### Shannon Entropy (`entropy.go`)
- Tính entropy theo công thức: `H = -Σ p(x) × log₂(p(x))`
- Entropy > 4.5 bits/byte → khả năng là dữ liệu mã hóa hoặc key bí mật
- Kết hợp với regex để giảm false positive trên dữ liệu binary

#### Classifier (`classifier.go`)
Tổng hợp điểm từ 3 thuật toán, áp dụng rule weight, trả về cấp độ cao nhất:

```
final_level = max(
    keyword_level × keyword_weight,
    regex_level × regex_weight,
    entropy_level × entropy_weight
)
```

---

### 4. Content Extractor (`internal/extractor/`)

Stream-based extraction để kiểm soát bộ nhớ:

| Format | Thư viện | Chiến lược |
|--------|----------|-----------|
| `.txt` | stdlib | Direct mmap read |
| `.docx` | `archive/zip` + `encoding/xml` | Extract `word/document.xml`, strip tags |
| `.pdf` | `github.com/ledongthuc/pdf` | Text layer only, bỏ qua image |
| `.xlsx` | `github.com/tealeg/xlsx` | Iterate cells, concat values |
| `.eml` | `net/mail` stdlib | Header + body, decode MIME |
| `.html` | `golang.org/x/net/html` | Tokenizer, skip script/style |

---

### 5. Scanner Core (`internal/scanner/`)

Trung tâm điều phối toàn bộ pipeline:

```
File path
    │
    ▼
Content Extractor  →  Raw text chunks (stream)
    │
    ▼
Rule Engine        →  []Match{Rule, Offset, Confidence}
    │
    ▼
Classifier         →  ScanResult{Level, Matches, Duration}
    │
    ▼
Result Aggregator  →  Ghi vào output channel
```

**mmap read**: Dùng `syscall.Mmap` để map file vào virtual memory thay vì đọc vào heap. Với file > 1 MB, tiết kiệm 60–80% RAM so với `ioutil.ReadAll`.

**Worker pool pattern**:
```go
sem := make(chan struct{}, maxWorkers)
for path := range fileChan {
    sem <- struct{}{}
    go func(p string) {
        defer func() { <-sem }()
        result := scanner.ScanFile(p)
        resultChan <- result
    }(path)
}
```

---

### 6. Agent Protocol (`internal/agent/`)

Hai mode giao tiếp:

**Unix Domain Socket** (local, latency thấp):
```json
// Request
{"action": "scan", "path": "/data/file.txt", "options": {"format": "json"}}

// Response
{"level": "CONFIDENTIAL", "matches": [...], "duration_ms": 12}
```

**gRPC** (distributed, cross-machine):
- Định nghĩa trong `proto/scanner.proto`
- Hỗ trợ unary RPC (`ScanFile`) và server-streaming RPC (`ScanDirectory`)
- TLS mutual authentication cho môi trường production

---

### 7. Output (`internal/output/`)

**CLI Output** (`cli.go`):
- `--format stdout`: Table view với màu theo level
- `--format csv`: `path,level,rule,confidence,offset`
- `--format json`: JSON array với full match details

**Audit Log** (`audit.go`):
- JSONL (JSON Lines) append-only, mỗi dòng là một ScanEvent
- Rotation theo kích thước (mặc định 100 MB) hoặc thời gian (mặc định hàng ngày)
- Format: `{"ts":"2025-01-01T00:00:00Z","path":"...","level":"CONFIDENTIAL","rule":"vn_id","offset":42}`

---

## Hiệu năng

| Metric | Target | Cơ chế đạt được |
|--------|--------|----------------|
| Throughput | 2M files/batch | Goroutine pool + channel pipeline |
| Accuracy | ≥ 98% | Multi-algorithm voting + context window |
| CPU per core | < 2% | mmap + Aho-Corasick O(n) scan |
| RAM working set | < 200 MB | Stream extraction + bounded pool |

---

## Phụ thuộc chính

```
golang.org/x/sync              v0.7.0   — errgroup, semaphore
github.com/BobuSumisu/aho-corasick v1.0.3 — Aho-Corasick implementation
github.com/ledongthuc/pdf       v0.6.0   — PDF text extraction
github.com/tealeg/xlsx          v1.0.5   — Excel reader
google.golang.org/grpc          v1.63.2  — gRPC framework
google.golang.org/protobuf      v1.34.1  — Protocol Buffers
gopkg.in/yaml.v3               v3.0.1   — Rule file parsing
```
