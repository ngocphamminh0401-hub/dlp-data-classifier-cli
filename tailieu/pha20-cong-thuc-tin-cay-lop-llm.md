# Pha 20 — Công thức tin cậy cho Lớp 2 (`conf_llm`) + kết hợp guardrail Pha 15

**Ngày:** 2026-09-18
**Yêu cầu:** xây công thức tính điểm tin cậy cho nhãn LLM (Lớp 2, phi4-mini), so sánh với
`conf_regex` (FileConfidence, Lớp 1): nếu `conf_llm < conf_regex` thì giữ nhãn regex; kết hợp với
guardrail Lớp 2 đã có (Pha 15).
**Script:** `scripts/notebooks/pha20a_call_full_l2.py` (thu thập dữ liệu) →
`scripts/notebooks/pha20b_conf_llm_fit.py` (fit `conf_llm`) →
`scripts/notebooks/pha20c_combined_policy_eval.py` (áp luật kết hợp + guardrail, đánh giá).
**Không đụng** `internal/engine/`, `rules/`, `pha10_refit.json`, cache Pha 12/15 gốc.

---

## 0. Bước chuẩn bị dữ liệu (Pha 20a)

`pha12_l2_preds.jsonl` gốc (Pha 12) chỉ lưu `label`, vứt `matched_rule`/`need_review`/`reason` dù
model có sinh ra. Pha 15 đã vá cho 232/1.487 file (nhóm CONFIDENTIAL→RESTRICTED). Pha 20a vá cho
**toàn bộ 1.487/1.487 file** Lớp 2 — gọi lại phi4-mini (cùng model/prompt/temperature=0, dùng lại
text cache có sẵn, không trích xuất lại file gốc), resumable, ghi cache riêng
`pha2out/pha20a_l2_full_preds.jsonl`. Chạy nền qua 2 lần (một lần dừng giữa chừng không rõ lý do ở
567/1.487, resume tiếp và hoàn tất) — tổng thời gian thực tế lâu hơn ước tính ban đầu (~11,2 s/file
đo ở Pha 12) do máy có lúc chạy chậm hơn (~53 s/file ở một đoạn), hoàn tất sau khoảng nhiều giờ chạy
rải rác trong ngày 2026-09-17/18.

Phân bố `matched_rule` (1.487 file): `public_published` 471, `pii_basic` 413, `special_category`
305, `internal_ops` 205, rỗng 28, `ma_strategy` 27, `financial_confidential` 25,
`legal_investigation` 8, `auth_secret` 5. `need_review=true`: 660/1.487 (44,4%) — rộng hơn nhiều so
với phạm vi 232 file CONF→RES mà Pha 15 từng đo, vì đây là field model tự gắn cho **mọi** quyết
định, không riêng nhóm escalate lên RESTRICTED.

---

## 1. Xây `conf_llm` (Pha 20b)

### 1.1. Nguyên tắc

- Target `y = (llm_label == ground_truth)` — "exact", cùng triết lý với Nhánh A của FileConfidence
  sau Pha 17 (không cho "qua" over-classification miễn phí).
- Fit bằng logistic regression (scikit-learn), **không** dùng lại chính dữ liệu để đánh giá: chia
  đôi ngẫu nhiên (seed cố định, stratify theo `exact`) 1.487 file thành `fit` (743) / `eval` (744).
  Đây là **Phương án B** đã thống nhất với người dùng (không gọi thêm LLM trên train+validation —
  ước tính tốn ~26,6 giờ theo Phương án A).
- Không Platt-calibrate thêm — `predict_proba` của logistic regression đã là xác suất trực tiếp,
  đủ dùng để so sánh thứ tự với `conf_regex` (mục đích chính là so sánh **tương đối**, không cần
  hiệu chỉnh ECE tuyệt đối ở bước này).

### 1.2. "Xem cách LLM suy luận" — đọc mẫu `reason`

Đọc 8 mẫu ĐÚNG + 8 mẫu SAI ngẫu nhiên. Quan sát:
- Mẫu ĐÚNG: `reason` cho `public_published`/`internal_ops` khá đồng nhất, công thức lặp lại
  ("Đã công bố công khai, không PII, không số liệu nội bộ chưa công bố") — model tự tin đúng khi
  văn bản rõ ràng công khai/nội bộ thường.
  chuẩn.
- Mẫu SAI: đa số là `special_category` (bệnh án/sức khỏe) bị gán RESTRICTED sai — đúng như phát
  hiện của Pha 13/15 (over-flag CONF→RES ở nhóm y tế). Một điểm đáng chú ý: `reason` của các case
  SAI này **văn phong không hề "phân vân"** — không có từ hedging, đọc y hệt câu văn của case ĐÚNG
  ("Dữ liệu sức khỏe, special category" / "Bệnh án có chẩn đoán gắn cá nhân") — model **tự tin
  nhầm**, không tự nhận biết được là mình sai. → giả thuyết ban đầu "ngôn ngữ hedging dự đoán được
  độ tin cậy" **không đúng cho nhóm lỗi nghiêm trọng nhất**; feature `reason_hedge` sau đó fit ra hệ
  số gần 0 (xác nhận quan sát định tính này bằng số).

### 1.3. Feature & hệ số (fit trên nửa `fit`, 743 file)

| feature | hệ số | ý nghĩa |
|---|---|---|
| `abs_jump` (số bậc LLM nhảy so với engine) | **−3,073** | mạnh nhất — nhảy càng nhiều bậc càng khó tin, khớp phát hiện Pha 13 (không có ngưỡng nào cho jump ≥2 an toàn) |
| `reason_digit` (reason có trích số cụ thể) | −1,460 | ngược trực giác ban đầu — sẽ bàn ở §1.4 |
| `engine_evidence` (engine tự có `special_category_signals`/`has_auth_secret`) | −1,159 | khi engine ĐÃ thấy tín hiệu tương ứng mà vẫn cần LLM sửa → thường là case biên khó, LLM cũng hay sai theo |
| `dom_hr` | −0,978 | domain HR khó hơn trung bình |
| `mr_strong` (matched_rule thuộc nhóm mạnh) | −0,867 | **ngược trực giác thiết kế guardrail Pha 15** — xem §1.4 |
| `need_review_i` | +0,584 | ngược trực giác — xem §1.4 |
| `jump` (có dấu) | +0,495 | |
| `mr_empty` | −0,237 | |
| `reason_len`, `reason_hedge` | ≈0 | không có thông tin — xác nhận quan sát định tính §1.2 |
| intercept | +2,808 | |

**AUC(exact):** `conf_llm` = 0,942 (fit) / **0,932 (eval, out-of-sample)** — phân biệt rất tốt
đúng/sai của chính nhãn LLM. Để đối chiếu, `conf_regex` đo AUC(exact-của-LLM) chỉ 0,555 (fit) /
0,515 (eval) — **gần như ngẫu nhiên**, đúng như kỳ vọng vì `conf_regex` được fit để đo độ tin cậy
của **engine**, không có thông tin gì về việc LLM đúng hay sai.

### 1.4. Vì sao vài hệ số "ngược trực giác" — và tại sao vẫn hợp lý

- **`mr_strong` âm**: nhóm `matched_rule` "mạnh" (`special_category`, `ma_strategy`,
  `legal_investigation`, `auth_secret`) mà Pha 15 dùng làm điều kiện CẦN để tin RESTRICTED, thực ra
  lại là nhóm **precision thấp nhất trong dữ liệu** — đa số occurrence của `special_category`
  (305 file) là các trường hợp escalate CONF→RES mà Pha 13/15 đã đo precision chỉ ~27-59% tùy cách
  tính. `mr_strong` "mạnh" theo nghĩa NỘI DUNG bằng chứng, không phải theo nghĩa THỐNG KÊ đáng tin —
  hai khái niệm khác nhau, và mô hình học đúng thống kê thực tế.
- **`need_review_i` dương**: mẫu need_review=true (660 file, 44%) phần lớn KHÔNG nằm trong nhóm
  CONF→RES biên (nơi Pha 15 quan sát need_review đúng nghĩa "phân vân") mà rải khắp — nhiều trường
  hợp model tự đánh dấu need_review cho các quyết định PUBLIC/INTERNAL bình thường mà nó vẫn đúng.
  Field này khi mở rộng ra toàn bộ 1.487 file (thay vì chỉ 232 file CONF→RES như Pha 15 đo) không
  còn giữ nguyên ý nghĩa "cờ báo nguy hiểm" — cần cẩn trọng khi diễn giải, KHÔNG dùng trực tiếp
  `need_review_i` dương này để nới lỏng guardrail (4) của Pha 15, vốn vẫn đúng trong phạm vi hẹp
  CONF→RES đã kiểm chứng.
- **`reason_digit` âm**: có trích số cụ thể trong `reason` tương quan với sai — giả thuyết: các
  case sai thường là "có nhiều PII/số liệu → chấm quá tay lên RESTRICTED" trong khi case đúng phần
  lớn là `public_published` (không có số liệu để trích).

**Kết luận §1**: `conf_llm` phân biệt rất tốt đúng/sai của LLM (AUC 0,93), nhưng driver mạnh nhất
là `abs_jump` — nghĩa là công thức chủ yếu học lại đúng thứ đã biết ("nhảy nhiều bậc = nguy hiểm"),
cộng thêm phát hiện mới quan trọng: **`matched_rule` "mạnh" theo thiết kế Pha 15 lại là tín hiệu
UNTIN CẬY về mặt thống kê** — đáng lưu ý cho việc tinh chỉnh guardrail sau này.

---

## 2. Luật kết hợp — Policy D (Pha 20c)

```
đề xuất escalate của LLM (li > pi) CHỈ được chấp nhận khi conf_llm ≥ conf_regex
                                    (ngược lại: giữ nhãn engine — escalate-only vẫn giữ nguyên)
  → cap +1 bậc (an toàn kép, dù abs_jump đã là feature mạnh nhất của conf_llm)
  → guardrail Pha 15 (1)+(3)+(4): matched_rule gate cho CONF→RES + need_review→human
```

Đánh giá **chỉ trên nửa `eval`** (744/1.487, out-of-sample với `conf_llm`) — so lại cả Policy
A/B/C (Pha 15) trên **cùng nửa eval này** để công bằng (Pha 15 gốc đo trên toàn bộ 1.487, không so
trực tiếp được với D).

### 2.1. Kết quả trên Lớp 2 (nửa eval, 744 file)

| Policy | accuracy | over | under | leak-recall toàn cục | leak-recall RESTRICTED (n=51) |
|---|---|---|---|---|---|
| A. baseline escalate-only | 65,1% | 31,2% | 3,8% | 0,725 | 0,549 |
| B. + cap +1 bậc | 67,3% | 28,5% | 4,2% | 0,696 | 0,490 |
| C. + guardrail Pha 15 | 72,4% | 20,6% | 7,0% | 0,490 | 0,078 |
| **D. MỚI (conf_llm gate + guardrail)** | **84,3%** | **3,8%** | 12,0% | **0,127** | **0,000** |

LLM đề xuất escalate 269/744 file (36,2%); cổng `conf_llm≥conf_regex` chỉ **chấp nhận 15/269
(5,6%)** — tức Policy D gần như luôn tin `conf_regex` hơn `conf_llm` khi có đề xuất nâng mức.

### 2.2. Ước lượng tổng pipeline (Layer 1 cố định 2.294 file theo Pha 12, Layer 2 = rate đo ở trên)

| Policy | accuracy | over | under |
|---|---|---|---|
| A | 77,7% | 20,1% | 2,2% |
| B | 78,6% | 19,0% | 2,4% |
| C (Pha 15, mốc hiện tại) | 80,6% | 15,9% | 3,5% |
| **D (mới)** | **85,3%** | **9,3%** | 5,4% |

---

## 3. Đọc đúng kết quả — KHÔNG kết luận vội "D tốt hơn C"

Nhìn thoáng qua, Policy D thắng rõ về accuracy (+4,7 điểm so với C) và over-classification (giảm
gần nửa, 15,9%→9,3%) — nhưng đây là **đánh đổi cực đoan về phía recall**, mạnh hơn nhiều so với bất
kỳ policy nào trước đó đã thử:

- **leak-recall RESTRICTED = 0,000** (0/51 file RESTRICTED bị engine bỏ sót được cứu) — so với
  Policy C đã thấp (0,078) thì D coi như **vô hiệu hóa hoàn toàn khả năng Lớp 2 cứu rò rỉ RESTRICTED
  tự động**. Đây là mức nguy hiểm nhất theo đúng phân loại DLP.
- **leak-recall INTERNAL cũng sụp** (0,868→0,132) — Policy D từ chối gần như mọi đề xuất escalate
  của LLM, kể cả những trường hợp trước đây phi4-mini cứu tốt (INTERNAL vốn là điểm mạnh của nó,
  xem Pha 13 §4).
- Đối chiếu với `RECALL_TARGET` đã chốt ở Pha 13 §4.1 (RESTRICTED ≥0,80, toàn cục ≥0,60) —
  **Policy D thất bại nặng cả hai** (0,000 và 0,127), còn tệ hơn cả baseline A (0,549 / 0,725).

**Nguyên nhân gốc**: `conf_llm` được fit để dự đoán "LLM có đúng không", và feature mạnh nhất là
`abs_jump` — hầu hết đề xuất escalate quan trọng (engine bỏ sót RESTRICTED, tức phải nhảy ≥1 bậc)
tự động nhận `conf_llm` thấp vì đúng bản chất "nhảy bậc" mà nó đang được huấn luyện để nghi ngờ. Kết
quả là cổng `conf_llm≥conf_regex` **loại bỏ đúng thứ mà Lớp 2 được thiết kế để làm** — nó tối ưu tốt
cho "đừng để LLM phá hỏng file engine đã đúng" nhưng lại xóa luôn phần "LLM cứu file engine bỏ sót".

## 4. Kết luận & khuyến nghị

1. **`conf_llm` xây được và hoạt động đúng như thiết kế** (AUC 0,93 out-of-sample) — nhưng dùng nó
   làm **cổng nhị phân thay thế hoàn toàn** cho escalate-only là **quá tay**, y hệt bài học Pha 13
   §1.D rút ra khi thử "LLM quyết định thay thẳng nhãn": một model dự đoán tốt "khi nào LLM đúng"
   không tự động là luật quyết định tốt cho DLP, vì DLP ưu tiên KHÔNG bỏ sót rò rỉ nghiêm trọng hơn
   là tối đa hóa accuracy thô.
2. **KHÔNG khuyến nghị đưa Policy D vào production ở dạng hiện tại** — vi phạm nghiêm trọng
   `RECALL_TARGET` RESTRICTED đã chốt (Pha 13 §4.1). Giữ **Policy C (guardrail Pha 15) là mốc hiện
   hành**.
3. **Hướng dùng `conf_llm` hợp lý hơn** (chưa làm, đề xuất cho pha sau):
   - Dùng `conf_llm` như **feature bổ sung vào chính guardrail (1)+(3)** thay vì thay thế nó — ví
     dụ: trong nhóm CONF→RES đã qua `matched_rule` gate, dùng `conf_llm` để **xếp hạng ưu tiên** hàng
     đợi `need_review` (file `conf_llm` thấp nhất xử lý trước) thay vì gate nhị phân loại bỏ.
   - Loại `abs_jump` khỏi feature của `conf_llm` (đã có cap+1 xử lý riêng) để tránh trùng lặp vai
     trò, xem `conf_llm` có còn phân biệt được gì THÊM ngoài số bậc nhảy không — nếu AUC rơi mạnh về
     gần 0,5 thì `conf_llm` hiện tại **chủ yếu là `abs_jump` đội lốt**, không phải tín hiệu độc lập
     mới.
   - Cân nhắc target khác cho `conf_llm`: thay vì "LLM đúng tuyệt đối", dùng "escalate của LLM có
     nên được tin" CHỈ trong tập con `li > pi` (loại bỏ nhiễu từ các quyết định PUBLIC/INTERNAL dễ
     mà LLM đúng phần lớn, đang làm loãng model).
4. **Phát hiện phụ có giá trị dù không dùng Policy D**: `mr_strong` (matched_rule "mạnh" theo thiết
   kế Pha 15) tương quan ÂM với việc LLM đúng trên toàn bộ 1.487 file — xác nhận lại bằng dữ liệu
   rộng hơn (thay vì chỉ 232 file) rằng whitelist `matched_rule` hiện tại của guardrail Pha 15 vẫn
   còn nhiều false positive, đúng như Pha 15 §4 đã ghi nhận nhưng giờ có cỡ mẫu lớn hơn để xác nhận.

## 5. Giới hạn

- Dùng Phương án B (chia đôi holdout hiện có) thay vì Phương án A (train+validation riêng) — mẫu
  `fit`/`eval` chỉ 743/744 file, nhỏ hơn nhiều so với các model FileConfidence (fit trên hàng nghìn
  file train+validation). Hệ số có thể kém ổn định hơn nếu chạy lại với seed khác.
  ⚠️ Ngoài ra: nửa `fit`/`eval` cùng lấy từ **holdout** — tập này trước giờ chỉ dùng để ĐÁNH GIÁ
  (Pha 12-19), chưa từng dùng để fit gì. Việc dùng một nửa holdout để fit `conf_llm` làm **holdout
  không còn "sạch" hoàn toàn** cho các đánh giá tổng thể tương lai liên quan đến Lớp 2 — cần ghi
  nhớ khi so sánh với các Pha trước.
- Không Platt-calibrate `conf_llm` — chỉ dùng `predict_proba` thô. Đủ cho mục đích so sánh thứ tự
  ở Pha này, nhưng nếu dùng `conf_llm` cho mục đích khác (vd. ngưỡng tuyệt đối) cần hiệu chỉnh lại.
- "Tổng pipeline" ở §2.2 là ước lượng (Layer 1 lấy cố định từ Pha 12, không đo lại) — không phải
  số đo trực tiếp trên toàn bộ 3.781 file holdout như các Pha trước.

## Kết quả thô

`pha2out/pha20a_l2_full_preds.jsonl` (1.487 dòng đủ field) · `pha2out/pha20b_conf_llm_model.json`
(hệ số + AUC) · `pha2out/pha20b_l2_with_conf.jsonl` (bảng đầy đủ, cột `cll_split`) ·
`pha2out/pha20c_combined_result.json` (kết quả policy A/B/C/D + ước lượng tổng pipeline).
