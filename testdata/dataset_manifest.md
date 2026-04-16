# Test Dataset Manifest

This dataset is designed to validate accuracy and reduce false positives.

## True Positive (TP)
| File | Format | Expected | Notes |
| --- | --- | --- | --- |
| testdata/positive/secret_credit_card_002.pdf | PDF | SECRET | Visa number + CVV + payment keywords |
| testdata/positive/confidential_vn_id_002.docx | DOCX | CONFIDENTIAL | CCCD keyword + 12-digit ID |
| testdata/positive/confidential_email_001.csv | CSV | CONFIDENTIAL | Email + CCCD column |
| testdata/positive/secret_api_key_001.env | ENV | SECRET | api_key label + long token |
| testdata/positive/secret_token_001.log | LOG | SECRET | access_token label + long JWT-like value |
| testdata/positive/secret_db_conn_001.go | Source | SECRET | connection_string with credentials |
| testdata/positive/secret_cccd_ocr_001.png | Image | CONFIDENTIAL (with OCR) | OCR required to extract text |

## True Negative (TN)
| File | Format | Expected | Notes |
| --- | --- | --- | --- |
| testdata/negative/clean_part_number_001.pdf | PDF | CLEAN | 16-digit part number (invalid Luhn, no keywords) |
| testdata/negative/clean_uuid_001.docx | DOCX | CLEAN | UUID only, no credential keywords |
| testdata/negative/clean_barcode_001.csv | CSV | CLEAN | Barcode column, no personal context |
| testdata/negative/clean_public_ip_001.log | LOG | CLEAN | Public IPs only |
| testdata/negative/clean_placeholder_001.md | Markdown | CLEAN | Placeholder api_key and password |
