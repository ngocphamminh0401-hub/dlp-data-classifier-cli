# Tổng hợp bộ rule DLP Classifier

Tự động tổng hợp từ `rules/rules.yaml` và các file rule trong `rules/`. Tổng cộng **52 rule đơn** + **17 compound rule**.

Cột **Gate**: có `level_gate` (yêu cầu ≥2 lần khớp cùng rule, hoặc rule khác ≥ CONFIDENTIAL trong cùng chunk, nếu không đủ thì hạ về `fallback_level`). Cột **Vol**: có `volume_escalation` (nâng level khi số lần khớp trong 1 file vượt ngưỡng, mặc định ≥50 → SECRET).

## PII (13 rule)

| ID | Tên | Level | Priority | Gate | Vol |
|---|---|---|---|---|---|
| `vn_id_001` | Căn cước công dân / CMND Việt Nam | CONFIDENTIAL | 80 | | ✓ |
| `passport_001` | Hộ chiếu Việt Nam | CONFIDENTIAL | 78 | | ✓ |
| `social_insurance_001` | Số BHXH / BHYT / Bảo hiểm xã hội | CONFIDENTIAL | 75 | | ✓ |
| `health_001` | Dữ liệu y tế / sức khỏe cá nhân (HEALTH_RESTRICTED không gate = SECRET; HEALTH_GENERAL override CONFIDENTIAL) | SECRET | 85 | | |
| `biometric_001` | Dữ liệu sinh trắc học (vân tay, khuôn mặt, mống mắt) | SECRET | 83 | | |
| `ethnicity_religion_political_001` | PII-010 Dân tộc / Tôn giáo / Đảng viên / Lý lịch chính trị | CONFIDENTIAL | 65 | | |
| `location_tracking_001` | PII-011 Dữ liệu vị trí / định vị / lịch sử di chuyển | CONFIDENTIAL | 63 | | |
| `phone_001` | Số điện thoại Việt Nam | INTERNAL | 55 | | |
| `email_001` | Địa chỉ email | INTERNAL | 45 | | ✓ |
| `dob_001` | Ngày tháng năm sinh | INTERNAL | 35 | | |
| `vn_name_001` | Họ tên người Việt Nam | INTERNAL | 30 | | |

## Financial (18 rule)

| ID | Tên | Level | Priority | Gate |
|---|---|---|---|---|
| `credit_card_001` | Thẻ tín dụng / ghi nợ quốc tế | SECRET | 100 | |
| `cvv_001` | CVV / CVC / CSC (mã bảo mật thẻ) | SECRET | 98 | ✓ |
| `otp_auth_001` | FIN-009 Mã OTP / PIN giao dịch / mã xác thực giao dịch | SECRET | 96 | |
| `otp_table_header_001` | FIN-010 Header bảng Số thẻ/CVV/OTP | SECRET | 91 | ✓ |
| `vip_customer_001` | FIN-011 Danh sách khách hàng VIP/ưu tiên (quy mô nhỏ vẫn SECRET) | SECRET | 90 | ✓ (fallback CONFIDENTIAL) |
| `fin_internal_chat_customer_data_001` | FIN-015 Chat nội bộ tiết lộ dữ liệu tài khoản khách hàng | CONFIDENTIAL | 88 | ✓ |
| `fin_credit_card_statement_001` | FIN-012 Sao kê thẻ tín dụng cá nhân | CONFIDENTIAL | 80 | ✓ (fallback INTERNAL) |
| `fin_transfer_confirmation_001` | FIN-014 Email xác nhận giao dịch chuyển khoản | CONFIDENTIAL | 78 | ✓ |
| `fin_account_statement_001` | FIN-013 Sao kê tài khoản thanh toán cá nhân | CONFIDENTIAL | 75 | ✓ (fallback INTERNAL) |
| `bank_account_001` | Số tài khoản ngân hàng Việt Nam | CONFIDENTIAL | 70 | | (vol ✓)
| `swift_bic_001` | Mã SWIFT/BIC ngân hàng | INTERNAL | 65 | |
| `tax_code_personal_001` | Mã số thuế cá nhân Việt Nam (13 số) | CONFIDENTIAL | 62 | |
| `tax_code_business_001` | Mã số thuế doanh nghiệp / chi nhánh Việt Nam | INTERNAL | 60 | |
| `iban_001` | Số tài khoản IBAN quốc tế | CONFIDENTIAL | 58 | |
| `income_001` | Thông tin lương / thu nhập / thù lao | CONFIDENTIAL | 52 | |
| `fin_internal_branch_financials_001` | FIN-020 Trao đổi nội bộ số liệu kinh doanh chi nhánh chưa kiểm toán | INTERNAL | 45 | ✓ (fallback PUBLIC) |
| `fin_compliance_report_001` | FIN-016 Báo cáo tuân thủ/giám sát định kỳ (không kèm PII/giao dịch cụ thể) | INTERNAL | 40 | ✓ |
| `fin_internal_training_guide_001` | FIN-017 Tài liệu đào tạo/hướng dẫn quy trình nghiệp vụ nội bộ | INTERNAL | 35 | ✓ |
| `fin_process_change_notice_001` | FIN-018 Thông báo thay đổi quy trình nghiệp vụ nội bộ | INTERNAL | 35 | ✓ |
| `fin_internal_risk_policy_discussion_001` | FIN-019 Trao đổi nội bộ xây dựng chính sách quản lý rủi ro | INTERNAL | 35 | ✓ |
| `fin_loan_approval_process_001` | FIN-021 Quy trình thẩm định/phê duyệt hồ sơ vay nội bộ | INTERNAL | 35 | ✓ |

## Org (15 rule)

| ID | Tên | Level | Priority | Gate |
|---|---|---|---|---|
| `credentials_001` | ORG-005 Thông tin kết nối DB / credentials | SECRET | 97 | |
| `classified_doc_001` | ORG-001 Tài liệu TỐI MẬT / MẬT / RESTRICTED | SECRET | 95 | ✓ (fallback CONFIDENTIAL) |
| `classified_doc_002` | ORG-001b Tài liệu BÍ MẬT / CONFIDENTIAL | CONFIDENTIAL | 94 | |
| `fraud_investigation_001` | ORG-006 Điều tra gian lận / AML / hình sự (CRIMINAL_AML, cố ý không gate) | SECRET | 93 | |
| `fraud_transaction_flag_001` | ORG-010 Giao dịch đáng ngờ/bất thường / rửa tiền (tên chính sách, dạng dễ phủ định) | CONFIDENTIAL | 88 | |
| `watermark_001` | Watermark nội bộ / nhãn lưu hành hạn chế | INTERNAL | 45 | |
| `insurance_context_001` | ORG-008 Ngữ cảnh hồ sơ bồi thường/claim bảo hiểm (tag phụ trợ cho compound) | CONFIDENTIAL | 45 | |
| `internal_ip_001` | ORG-004 Địa chỉ IP nội bộ (Private) | INTERNAL | 50 | |
| `contract_001` | ORG-003 Mã số hợp đồng / PO | CONFIDENTIAL | 60 | |
| `vnpt_email_001` | Email domain nội bộ VNPT (tín hiệu tổ chức) | INTERNAL | 42 | |
| `internal_code_001` | Mã nội bộ và nhãn phân loại VNPT | INTERNAL | 40 | |
| `business_internal_specific_001` | ORG-009 Từ vựng nghiệp vụ nội bộ đặc thù ngân hàng/bảo hiểm | INTERNAL | 39 | |
| `business_internal_001` | ORG-007 Văn bản nghiệp vụ nội bộ thông thường (catch-all) | INTERNAL | 38 | ✓ (fallback PUBLIC) |

## HR (7 rule)

| ID | Tên | Level | Priority | Gate |
|---|---|---|---|---|
| `hr_internal_chat_protected_attributes_001` | HR-003 Chat nội bộ tiết lộ lý do sa thải kèm thuộc tính được bảo vệ | RESTRICTED | 92 | ✓ (fallback CONFIDENTIAL) |
| `hr_sexual_harassment_complaint_001` | HR-020 Hồ sơ/đơn khiếu nại quấy rối tình dục nơi làm việc | RESTRICTED | 92 | ✓ |
| `hr_party_membership_dossier_001` | HR-001 Hồ sơ xét kết nạp Đảng (lý lịch chính trị cá nhân/thân nhân) | RESTRICTED | 88 | ✓ (fallback INTERNAL) |
| `hr_workplace_accident_investigation_001` | HR-021 Biên bản điều tra tai nạn lao động kèm dữ liệu y tế nạn nhân | RESTRICTED | 88 | ✓ |
| `hr_disciplinary_health_investigation_001` | HR-002 Biên bản xác minh kỷ luật liên quan sức khỏe cá nhân | RESTRICTED | 85 | ✓ |
| `hr_offer_letter_001` | HR-022 Thư mời nhận việc kèm đãi ngộ cá nhân | CONFIDENTIAL | 85 | ✓ (fallback INTERNAL) |
| `hr_internal_business_001` | HR-030 Văn bản nghiệp vụ nhân sự nội bộ thông thường (catch-all) | INTERNAL | 39 | ✓ (fallback PUBLIC) |

## Compound rules (17)

Kết hợp ≥2 rule/category cùng khớp trong 1 chunk để nâng level. `min_component_level` (nếu có) yêu cầu MỌI điều kiện phải đạt tối thiểu mức đó (không chỉ có mặt).

| Tên | Điều kiện | Kết quả | Ghi chú |
|---|---|---|---|
| Credit card + CVV = SECRET | `credit_card`, `cvv` | SECRET | PCI-DSS Req.3.3.1 |
| Credentials + Internal IP = SECRET | `credentials`, `internal_ip` | SECRET | |
| Credentials + Identity = SECRET | `credentials`, `pii_vn_id` | SECRET | Account takeover enabler |
| VNPT email + Classified SECRET = SECRET | `vnpt_email`, `classified_doc_001` | SECRET | `min_component_level: SECRET` (tránh hồi sinh match đã bị gate hạ) |
| Location Tracking + Financial = SECRET | `pii_location_tracking`, `financial` | SECRET | `min_component_level: CONFIDENTIAL` |
| Health + Insurance Context = SECRET | `pii_health`, `org_insurance_context` | SECRET | `min_component_level: CONFIDENTIAL`. **Load-bearing**: chịu trách nhiệm ~31% RESTRICTED thật của domain insurance — đã kiểm chứng không được gỡ/sửa |
| Ethnicity/Religion + Identity (CCCD) = SECRET | `pii_ethnicity_religion_political`, `pii_vn_id` | SECRET | `min_component_level: CONFIDENTIAL` |
| Ethnicity/Religion + Passport = SECRET | `pii_ethnicity_religion_political`, `pii_passport` | SECRET | nt |
| Ethnicity/Religion + Social Insurance = SECRET | `pii_ethnicity_religion_political`, `pii_social_insurance` | SECRET | nt |
| Ethnicity/Religion + Financial = SECRET | `pii_ethnicity_religion_political`, `financial` | SECRET | nt |
| Ethnicity/Religion + Health = SECRET | `pii_ethnicity_religion_political`, `pii_health` | SECRET | nt — 5 rule này đảo ngược quyết định "không tự leo thang" ban đầu sau khi có dữ liệu HR thật |
| VNPT email + Classified CONFIDENTIAL = CONFIDENTIAL | `vnpt_email`, `classified_doc_002` | CONFIDENTIAL | |
| Contract + Financial = CONFIDENTIAL | `org_contract`, `financial` | CONFIDENTIAL | |
| Contract + PII = CONFIDENTIAL | `org_contract`, `pii` | CONFIDENTIAL | |
| Phone + Financial = CONFIDENTIAL | `pii_phone`, `financial` | CONFIDENTIAL | |
| PII Aggregation (email + phone + DOB) = CONFIDENTIAL | `pii_email`, `pii_phone`, `pii_dob` | CONFIDENTIAL | Re-identification risk (GDPR Recital 26) |
| Internal IP + Internal Code = CONFIDENTIAL | `org_internal_ip`, `org_internal_code` | CONFIDENTIAL | Network recon risk |

## Ghi chú thiết kế quan trọng

- **Corroboration của `level_gate`** chỉ tính: (a) match đã qua validator, HOẶC (b) rule khớp ≥2 lần trong chunk, HOẶC (c) có rule khác ≥ CONFIDENTIAL trong cùng chunk — **không phân biệt được loại tín hiệu**, nên với văn bản PII-rich, điều kiện (c) gần như luôn tự thỏa mãn dù tín hiệu gốc chỉ là 1 lần nhắc yếu.
- **Ngưỡng confidence**: điểm cuối = `pattern.confidence × rule.weight`, so với `engine.MinConfidence` mặc định 0.60. Rule có `weight` thấp (VD 0.75) cần pattern `confidence ≥ 0.80` mới chắc chắn vượt ngưỡng dù không có context boost.
- **RE2 (Go regexp) không hỗ trợ lookaround** — không loại trừ được tiền tố phủ định ("không có", "không yêu cầu") hay hậu tố. Nhiều rule (đặc biệt `fraud_investigation_001`/`fraud_transaction_flag_001`/`health.yaml`) đã phải tách "diễn đạt cụ thể" (giữ SECRET) khỏi "cụm từ dễ bị phủ định/mang tính chính sách chung" (hạ CONFIDENTIAL) để giảm false positive thay vì cố loại trừ trực tiếp.
- **`false_positive_reduction.exclude_patterns`** và **`level_gate.min_pattern_matches`** KHÔNG tồn tại trong schema engine (`internal/engine/rules.go`) — nếu thấy trong rule nháp, phải xóa (bị bỏ qua âm thầm, không lỗi).
