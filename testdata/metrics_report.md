# Evaluation Metrics

- Evaluated files: 15
- Accuracy (exact level): 0.8667
- Binary Precision (sensitive vs clean): 1.0000
- Binary Recall (sensitive vs clean): 0.7500
- Binary F1 (sensitive vs clean): 0.8571
- Macro Precision (4 levels): 0.6944
- Macro Recall (4 levels): 0.6167
- Macro F1 (4 levels): 0.6410

## Per-level metrics

| Level | Support | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PUBLIC | 7 | 7 | 2 | 0 | 0.7778 | 1.0000 | 0.8750 |
| INTERNAL | 0 | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 |
| CONFIDENTIAL | 3 | 2 | 0 | 1 | 1.0000 | 0.6667 | 0.8000 |
| SECRET | 5 | 4 | 0 | 1 | 1.0000 | 0.8000 | 0.8889 |

## Binary confusion

| Metric | Value |
| --- | ---: |
| TP | 6 |
| FP | 0 |
| FN | 2 |

## Mismatches

| Kind | Path | Expected | Predicted |
| --- | --- | --- | --- |
| false-negative | testdata/positive/confidential_vn_id_002.docx | CONFIDENTIAL | PUBLIC |
| false-negative | testdata/positive/secret_credit_card_002.pdf | SECRET | PUBLIC |
