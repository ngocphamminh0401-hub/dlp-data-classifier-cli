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

	// wrapIndentThreshold: 1 dòng vật lý (band) mới bắt đầu LỆCH PHẢI hơn lề
	// trái đã xác lập quá ngưỡng này (pt) bị coi là DÒNG WRAP TIẾP THEO của 1
	// Ô BẢNG ở hàng trên (không phải hàng bảng/đoạn văn mới) — xem giải thích
	// đầy đủ tại reconstructLayout.
	wrapIndentThreshold = 15.0
)

// reconstructLayout dựng lại văn bản đọc được từ danh sách ký tự có toạ độ
// (mỗi phần tử là 1 ký tự — xem Page.Content()), theo đúng thứ tự hiển thị
// trái→phải, trên→dưới thay vì thứ tự vẽ trong content stream.
//
// Vấn đề đã sửa (xác nhận qua fin_top_00014.pdf, health_conf_00206.pdf,
// ins_top_00252.pdf — bảng có cột hẹp khiến giá trị wrap xuống dòng): thuật
// toán CŨ nhóm ký tự thành "dòng" (band) THUẦN theo toạ độ Y bằng nhau, rồi
// LUÔN xuống dòng mới (\n) mỗi khi sang band khác — không phân biệt được
// band đó là 1 HÀNG BẢNG MỚI hay chỉ là DÒNG WRAP THỨ 2 của 1 ô trong CÙNG
// hàng cũ (VD ô "Họ và tên" hẹp khiến "Phạm Đình Khánh" wrap thành "Phạm" +
// "Đình Khánh" ở 2 band Y khác nhau). Khi các ô trong 1 hàng wrap số dòng
// khác nhau, các dòng wrap trôi lệch Y và bị in xen kẽ với ô KHÁC ở band đó
// — xé tên/số tài khoản/từ khoá ra nhiều mảnh không liền nhau, khiến regex
// downstream (context_required, exclude_if_no_keywords...) không khớp được.
//
// Heuristic: 1 dòng wrap của Ô BẢNG (không phải hàng/đoạn mới) luôn bắt đầu
// LỆCH PHẢI đáng kể so với LỀ TRÁI của bảng/đoạn (X của cột đầu tiên, VD cột
// STT) — vì nó là phần tiếp theo của 1 ô nằm ở cột giữa/cuối bảng, không bao
// giờ bắt đầu lại từ cột đầu. Ngược lại, dòng văn xuôi thường (kể cả xuống
// dòng tự nhiên do PDF wrap theo bề rộng trang) luôn bắt đầu LẠI ở lề trái
// (mỗi dòng văn xuôi được PDF renderer đặt Td riêng tại cùng X lề trái) nên
// không bị ảnh hưởng. Band lệch phải > wrapIndentThreshold so với lề trái đã
// biết → GỘP vào cuối dòng hiện tại (nối bằng 1 dấu cách) thay vì xuống dòng
// mới — giữ toàn bộ nội dung của 1 hàng bảng liền mạch trên 1 dòng output.
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

	// Pass 1: nhóm ký tự thành các "band" (dòng vật lý theo Y), giữ nguyên
	// thứ tự và X nhỏ nhất của mỗi band — CHƯA quyết định band nào là hàng
	// mới/dòng wrap ở bước này.
	type band struct {
		chars []pdf.Text
		minX  float64
	}
	var bands []band
	var rowY float64
	haveRow := false
	for _, c := range sorted {
		if !haveRow || math.Abs(c.Y-rowY) > rowTolerance {
			bands = append(bands, band{minX: c.X})
			rowY = c.Y
			haveRow = true
		} else if c.X < bands[len(bands)-1].minX {
			bands[len(bands)-1].minX = c.X
		}
		bands[len(bands)-1].chars = append(bands[len(bands)-1].chars, c)
	}

	// renderBand: dựng text trong nội bộ 1 band (logic khoảng cách trong-
	// dòng giữ nguyên như thuật toán cũ).
	renderBand := func(b band) string {
		var buf bytes.Buffer
		var prevEndX, prevFontSize float64
		first := true
		for _, c := range b.chars {
			if !first {
				gap := c.X - prevEndX
				threshold := wordGapFactor * math.Max(prevFontSize, c.FontSize)
				if threshold <= 0 {
					threshold = 1
				}
				switch {
				case gap > cellGapAbsolute:
					buf.WriteString("  ")
				case gap > threshold:
					buf.WriteByte(' ')
				}
			}
			buf.WriteString(c.S)
			if endX := c.X + c.W; endX > prevEndX {
				prevEndX = endX
			}
			if c.FontSize > 0 {
				prevFontSize = c.FontSize
			}
			first = false
		}
		return buf.String()
	}

	// Pass 2: quyết định mỗi band là HÀNG MỚI (xuống dòng \n, cập nhật lề
	// trái) hay DÒNG WRAP (gộp vào cuối dòng output hiện tại).
	var out bytes.Buffer
	leftMargin := math.Inf(1)
	haveMargin := false
	first := true
	for _, b := range bands {
		text := renderBand(b)
		if text == "" {
			continue
		}
		isWrap := haveMargin && (b.minX-leftMargin) > wrapIndentThreshold
		if isWrap {
			out.WriteByte(' ')
			out.WriteString(text)
			continue
		}
		if !first {
			out.WriteByte('\n')
		}
		out.WriteString(text)
		if !haveMargin || b.minX < leftMargin {
			leftMargin = b.minX
		}
		haveMargin = true
		first = false
	}

	return out.String()
}
