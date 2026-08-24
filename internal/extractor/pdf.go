package extractor

import (
	"bytes"
	"math"
	"sort"

	pdf "github.com/ledongthuc/pdf"
)

// ExtractPDF extracts text layer content from a PDF file.
//
// Không dùng Reader.GetPlainText(): nó nối các đoạn Tj/TJ theo THỨ TỰ VẼ
// trong content stream, không theo vị trí hiển thị (X/Y). Với PDF do các
// công cụ dựng bảng tạo ra (vẽ theo cột thay vì theo hàng, hoặc chèn từng
// đoạn text nhỏ rải rác), thứ tự vẽ khác hẳn thứ tự đọc thật — chữ bị xáo
// trộn, ghép sai giữa các ô, quan sát thấy trên các file báo cáo/danh sách
// dạng bảng (VD: "Ngày sinh" → "Ngàyàsinhà": ký tự từ ô khác chen vào giữa
// từ) và khiến regex theo nhãn (label) không match được giá trị thật.
//
// Thay vào đó dùng Page.Content() — trả về toạ độ (X, Y) chính xác của
// TỪNG ký tự (đã áp dụng đầy đủ text matrix, kể cả Td/TD) — rồi tự dựng lại
// văn bản theo đúng thứ tự đọc: nhóm ký tự cùng hàng theo Y, sắp theo X
// trong hàng, hàng sắp theo Y giảm dần (Y trong PDF tăng từ dưới lên).
func ExtractPDF(path string) ([]byte, error) {
	f, r, err := pdf.Open(path)
	if err != nil {
		return nil, wrapErr(path, "open_pdf", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	pages := r.NumPage()
	for i := 1; i <= pages; i++ {
		p := r.Page(i)
		if p.V.IsNull() {
			continue
		}
		content, cerr := safePageContent(p)
		if cerr != nil {
			return nil, wrapErr(path, "page_content", cerr)
		}
		if buf.Len() > 0 && len(content.Text) > 0 {
			buf.WriteString("\n\n")
		}
		buf.WriteString(reconstructLayout(content.Text))
	}
	return buf.Bytes(), nil
}

// safePageContent bọc Page.Content() — thư viện ledongthuc/pdf panic khi gặp
// content stream dị dạng thay vì trả lỗi (xem cách GetPlainText tự recover).
func safePageContent(p pdf.Page) (content pdf.Content, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errPanic(rec)
		}
	}()
	return p.Content(), nil
}

func errPanic(rec any) error {
	if e, ok := rec.(error); ok {
		return e
	}
	return &panicError{rec}
}

type panicError struct{ v any }

func (e *panicError) Error() string { return "panic: " + toString(e.v) }

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if err, ok := v.(error); ok {
		return err.Error()
	}
	return "unknown"
}

// Dung sai/ngưỡng dựng layout, tính bằng point (1/72 inch) — đơn vị toạ độ
// PDF gốc. Tinh chỉnh dựa trên các file báo cáo dạng bảng thực tế trong
// dataset đánh giá (xem scripts/eval_restricted.go).
const (
	// rowTolerance: 2 ký tự coi là cùng 1 hàng nếu |ΔY| ≤ ngưỡng này.
	// Bù sai số làm tròn nhỏ trong text matrix, không đủ lớn để gộp nhầm
	// 2 hàng bảng liền kề (thường cách nhau ≥ 10pt với cỡ chữ thông thường).
	rowTolerance = 2.0

	// wordGapFactor: hệ số nhân với font size để suy ra khoảng cách "trong
	// một từ" (không chèn space) — khoảng trống nhỏ do bo tròn giữa 2 lần
	// vẽ ký tự liên tiếp không nên tách từ.
	wordGapFactor = 0.28

	// cellGapAbsolute: khoảng cách X (pt) đủ lớn để coi là ranh giới ô/cột
	// trong bảng — chèn 2 space để giữ tín hiệu "đây là ô khác" cho người
	// đọc log, dù engine chỉ cần ≥1 space để tách từ khi match regex.
	cellGapAbsolute = 6.0
)

// reconstructLayout dựng lại văn bản đọc được từ danh sách ký tự có toạ độ
// (mỗi phần tử là 1 ký tự — xem Page.Content()), theo đúng thứ tự hiển thị
// trái→phải, trên→dưới thay vì thứ tự vẽ trong content stream.
func reconstructLayout(chars []pdf.Text) string {
	if len(chars) == 0 {
		return ""
	}

	sorted := make([]pdf.Text, len(chars))
	copy(sorted, chars)
	sort.SliceStable(sorted, func(i, j int) bool {
		if math.Abs(sorted[i].Y-sorted[j].Y) > rowTolerance {
			return sorted[i].Y > sorted[j].Y // Y giảm dần = đọc từ trên xuống
		}
		return sorted[i].X < sorted[j].X
	})

	var out bytes.Buffer
	var rowY float64
	haveRow := false
	var prevEndX, prevFontSize float64
	first := true

	for _, c := range sorted {
		if !haveRow || math.Abs(c.Y-rowY) > rowTolerance {
			if !first {
				out.WriteByte('\n')
			}
			rowY = c.Y
			haveRow = true
			prevEndX = c.X
			prevFontSize = c.FontSize
		} else {
			gap := c.X - prevEndX
			threshold := wordGapFactor * math.Max(prevFontSize, c.FontSize)
			if threshold <= 0 {
				threshold = 1
			}
			switch {
			case gap > cellGapAbsolute:
				out.WriteString("  ")
			case gap > threshold:
				out.WriteByte(' ')
			}
		}
		out.WriteString(c.S)
		if endX := c.X + c.W; endX > prevEndX {
			prevEndX = endX
		}
		if c.FontSize > 0 {
			prevFontSize = c.FontSize
		}
		first = false
	}

	return out.String()
}
