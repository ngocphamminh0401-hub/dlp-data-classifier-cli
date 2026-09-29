# %% [markdown]
# # Pha 20b — Xây `conf_llm`: điểm tin cậy cho nhãn Lớp 2 (phi4-mini)
#
# Mục tiêu: một thang điểm tin cậy cho nhãn LLM, CÙNG THANG với `conf_regex` (FileConfidence
# V-Pha10), để so sánh trực tiếp `conf_llm vs conf_regex` khi quyết định có chấp nhận đề xuất
# escalate của LLM hay không (Pha 20c).
#
# Dữ liệu: toàn bộ 1.487 file Lớp 2 (holdout, `conf_regex<0.95`), đủ `matched_rule`/`need_review`/
# `reason` từ `pha20a_l2_full_preds.jsonl` (vừa chạy xong đủ 1.487/1.487, thay cho bản chỉ có
# 232 file của Pha 15). Target `y = (llm_label == ground_truth)` — "exact", cùng triết lý Pha 17.
#
# Kỷ luật tránh leakage: KHÔNG fit rồi eval trên cùng dữ liệu. Chia đôi ngẫu nhiên (seed cố định)
# 1.487 file thành `fit` (fit công thức) / `eval` (dành riêng cho Pha 20c đánh giá cuối, KHÔNG
# đụng ở bước này). Đây là Phương án B đã chốt với người dùng (không gọi thêm LLM trên
# train+validation — tốn ~26 giờ theo ước tính Phương án A).
#
# Không đụng `internal/engine/`, `rules/`, `pha10_refit.json`, cache Pha 12/15 gốc (chỉ đọc).

# %%
from __future__ import annotations
import json, pathlib, re
import numpy as np, pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

OUT = pathlib.Path("pha2out")
LVL = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
LVL_IDX = {l: i for i, l in enumerate(LVL)}
STRONG_RULES = {"auth_secret", "special_category", "legal_investigation", "ma_strategy"}
SEED = 20260918
HEDGE_WORDS = ["có thể", "có lẽ", "không chắc", "chưa rõ", "khó xác định", "nghi ngờ",
               "phân vân", "không rõ", "dường như", "có khả năng", "chưa chắc"]

# ── FileConfidence V-PHA10 (giống pha12/pha15 — copy để độc lập, không import chéo notebook) ──
M = json.loads((OUT / "pha10_refit.json").read_text(encoding="utf-8"))
GA, G0A, KA = M["branch_A"]["gamma"], M["branch_A"]["gamma0"], M["branch_A"]["k"]
GB, B0B, KB, PLATT = M["branch_B"]["beta"], M["branch_B"]["beta0"], M["branch_B"]["k"], M["branch_B"]["platt"]
HIGH_DEFAULT = float(json.loads((OUT / "pha5_result.json").read_text(encoding="utf-8"))["high_default"])
FP_PRONE = {"health_001", "bank_account_001", "credentials_001"}
ALWAYS_SECRET = {"credit_card_001", "cvv_001", "otp_auth_001", "credentials_001", "fraud_investigation_001"}
T1 = 0.95


def phi(x, k):
    return 1.0 - np.exp(-np.asarray(x, float) / k)


tr = pd.read_json(OUT / "features_split.jsonl", lines=True)
tr["gi"] = tr.ground_truth_level.map(LVL_IDX)
tr["pi"] = tr.predicted_level.map(LVL_IDX)
trA = tr[(tr.split == "train") & tr.branch_a_applicable.fillna(False)].copy()
trA["dec"] = trA.decisive_rule_ids.apply(lambda v: list(v) if isinstance(v, (list, np.ndarray)) else [])


def _prec(s):
    tot, ok = {}, {}
    for ids, gi, pi in zip(s.dec, s.gi, s.pi):
        for r in ids:
            tot[r] = tot.get(r, 0) + 1
            ok[r] = ok.get(r, 0) + int(gi <= pi)
    return {r: (ok[r] + (0.70 if r in FP_PRONE else 0.90) * 10) / (tot[r] + 10) for r in tot}


def _up(s):
    tot, u = {}, {}
    for ids, y in zip(s.matched_rule_ids, (s.gi > s.pi).astype(int)):
        for r in (ids if isinstance(ids, (list, np.ndarray)) else []):
            tot[r] = tot.get(r, 0) + 1
            u[r] = u.get(r, 0) + y
    return {r: (u[r] + 0.10 * 12) / (tot[r] + 12) for r in tot}


PREC, UP = _prec(trA), _up(trA)
prec = lambda r: PREC.get(r, 0.70 if r in FP_PRONE else 0.90)
up = lambda r: UP.get(r, 0.10)

ho = tr[tr.split == "holdout"].copy().reset_index(drop=True)
ho["gi"] = ho.ground_truth_level.map(LVL_IDX)
ho["pi"] = ho.predicted_level.map(LVL_IDX)
ho["dec"] = ho.decisive_rule_ids.apply(lambda v: list(v) if isinstance(v, (list, np.ndarray)) else [])
ho["mids"] = ho.matched_rule_ids.apply(lambda v: list(v) if isinstance(v, (list, np.ndarray)) else [])
ho["scs_nonempty"] = ho.special_category_signals.apply(
    lambda v: isinstance(v, (list, np.ndarray)) and len(v) > 0)


def conf_row(r):
    dom, lvl = r.domain, int(r.pi)
    always = any(x in ALWAYS_SECRET for x in r.mids) or ("health_001" in r.mids and lvl == 3)
    branch_a = bool(r.branch_a_applicable) and len(r.dec) > 0
    err = (r.chunk_error_ratio or 0) > 0.30
    short = (r.file_effective_length or 0) < 200
    isA = branch_a or always or (r.match_count > 0 and lvl > 0 and not branch_a and not err)
    if isA:
        risk = 1 - min((prec(x) for x in r.dec), default=0.5) if r.dec else 0.30
        upv = max((up(x) for x in r.mids), default=0.10)
        z = G0A.get(dom, GA["const"])
        z += GA["risk"] * risk + GA["under_propensity"] * upv
        z += GA["numeric"] * phi(r.unstructured_numeric_hits or 0, KA["numeric"])
        z += GA["compound_near_miss"] * phi(r.compound_near_miss_score or 0, KA["cnm"])
        z += GA["escalation_near_miss"] * phi(r.escalation_near_miss_score or 0, KA["esc"])
        z += GA["validator_fail_ctx"] * phi(r.validator_fail_in_context_count or 0, KA["vfc"])
        z += GA["level_gate_A"] * phi(r.level_gate_downgrade_count or 0, KA["lgd"])
        z += GA["hr_probe_A"] * phi(r.hr_sensitive_lexicon_no_rule_count or 0, KA["hrp"])
        c = 1 / (1 + np.exp(-z))
        if lvl == 3 or always:
            c = max(c, 0.97)
        return c, "A"
    if err:
        return np.nan, "error"
    if short:
        return HIGH_DEFAULT, "short"
    numd = (r.unstructured_numeric_hits or 0) / max((r.file_effective_length or 0) / 1000, 1e-9)
    z = B0B.get(dom, GB["const"])
    z += GB["b_kw"] * phi(r.keyword_hit_no_match_primary_rules or 0, KB["kw"])
    z += GB["b_prox"] * phi(r.proximity_reject_count or 0, KB["prox"])
    z += GB["b_lgd"] * phi(r.level_gate_downgrade_count or 0, KB["lgd"])
    z += GB["b_numd"] * phi(numd, KB["numd"])
    z += GB["b_docctx"] * (1.0 if (r.doc_context_discount_count or 0) > 0 else 0.0)
    z += GB["b_hr"] * phi(r.hr_sensitive_lexicon_no_rule_count or 0, KB["hr"])
    c = 1 / (1 + np.exp(-z))
    lz = np.log(np.clip(c, 1e-6, 1 - 1e-6) / (1 - np.clip(c, 1e-6, 1 - 1e-6)))
    return 1 / (1 + np.exp(-(PLATT["a"] * lz + PLATT["b"]))), "B"


cb = ho.apply(conf_row, axis=1)
ho["conf_regex"] = [x[0] for x in cb]
ho["branch"] = [x[1] for x in cb]
ho = ho[ho.branch != "error"].copy().reset_index(drop=True)
ho["has_auth_secret_v"] = ho.get("has_auth_secret", pd.Series(False, index=ho.index)).fillna(False)

# ── nhãn LLM gốc (llm_label, 1.487 file conf<0.95) + đủ field mới (pha20a, full 1.487) ──
llm_label = {}
for l in (OUT / "pha12_l2_preds.jsonl").read_text(encoding="utf-8").splitlines():
    if l.strip():
        d = json.loads(l)
        if d.get("llm_label") in LVL_IDX:
            llm_label[d["file_id"]] = d["llm_label"]

full = {}
for l in (OUT / "pha20a_l2_full_preds.jsonl").read_text(encoding="utf-8").splitlines():
    if l.strip():
        d = json.loads(l)
        full[d["file_id"]] = d

ho["llm_label"] = ho.file_id.map(llm_label)
ho["li"] = ho.llm_label.map(LVL_IDX)
ho["matched_rule"] = ho.file_id.map(lambda f: full.get(f, {}).get("matched_rule", ""))
ho["need_review"] = ho.file_id.map(lambda f: bool(full.get(f, {}).get("need_review", False)))
ho["reason"] = ho.file_id.map(lambda f: full.get(f, {}).get("reason", ""))

route = ho.conf_regex < T1
has_label = route & ho.li.notna() & ho.file_id.isin(full.keys())
L2 = ho[has_label].copy().reset_index(drop=True)
print(f"Holdout dùng được: {len(ho)} | route (conf_regex<{T1}): {int(route.sum())} | "
      f"có đủ nhãn+field mới: {len(L2)}")

# %% [markdown]
# ## Đọc mẫu định tính `reason` (đúng vs sai) trước khi feature-engineer

# %%
L2["li"] = L2.li.astype(int)
L2["exact"] = (L2.li == L2.gi).astype(int)
print(f"y=1 rate (llm_label khớp ground_truth) trên toàn bộ L2 có nhãn: {L2.exact.mean():.1%}")
rng = np.random.RandomState(SEED)
samp_ok = L2[L2.exact == 1].sample(min(8, (L2.exact == 1).sum()), random_state=SEED)
samp_bad = L2[L2.exact == 0].sample(min(8, (L2.exact == 0).sum()), random_state=SEED)
print("\n--- mẫu reason ĐÚNG ---")
for _, r in samp_ok.iterrows():
    print(f"  [{r.matched_rule or '(rỗng)'} nr={r.need_review}] {r.reason!r}")
print("\n--- mẫu reason SAI ---")
for _, r in samp_bad.iterrows():
    print(f"  [{r.matched_rule or '(rỗng)'} nr={r.need_review}] {r.reason!r}")

# %% [markdown]
# ## Feature engineering cho `conf_llm`

# %%
def has_hedge(s):
    s = (s or "").lower()
    return int(any(w in s for w in HEDGE_WORDS))


def has_digit(s):
    return int(bool(re.search(r"\d", s or "")))


L2["jump"] = L2.li - L2.pi
L2["abs_jump"] = L2.jump.abs()
L2["mr_strong"] = L2.matched_rule.isin(STRONG_RULES).astype(int)
L2["mr_empty"] = (L2.matched_rule.fillna("") == "").astype(int)
L2["engine_evidence"] = (L2.scs_nonempty | L2.has_auth_secret_v).astype(int)
L2["reason_len"] = L2.reason.fillna("").str.len()
L2["reason_hedge"] = L2.reason.apply(has_hedge)
L2["reason_digit"] = L2.reason.apply(has_digit)
L2["need_review_i"] = L2.need_review.astype(int)

FEATS = ["need_review_i", "jump", "abs_jump", "mr_strong", "mr_empty", "engine_evidence",
          "reason_len", "reason_hedge", "reason_digit"]
DOM_DUMMIES = pd.get_dummies(L2.domain, prefix="dom", drop_first=True)
X_all = pd.concat([L2[FEATS].astype(float), DOM_DUMMIES.astype(float)], axis=1)
y_all = L2.exact.to_numpy()

fit_idx, eval_idx = train_test_split(np.arange(len(L2)), test_size=0.5, random_state=SEED,
                                      stratify=L2.exact)
L2.loc[fit_idx, "cll_split"] = "fit"
L2.loc[eval_idx, "cll_split"] = "eval"
print(f"\nChia: fit={len(fit_idx)} eval={len(eval_idx)}  "
      f"(y=1 rate fit={y_all[fit_idx].mean():.1%}, eval={y_all[eval_idx].mean():.1%})")

Xf, yf = X_all.iloc[fit_idx], y_all[fit_idx]
Xe, ye = X_all.iloc[eval_idx], y_all[eval_idx]

clf = LogisticRegression(max_iter=2000, C=1.0)
clf.fit(Xf, yf)
coef = dict(zip(X_all.columns, clf.coef_[0].tolist()))
print("\nHệ số logistic (fit trên nửa `fit`):")
for k, v in sorted(coef.items(), key=lambda kv: -abs(kv[1])):
    print(f"  {k:>18s}: {v:+.3f}")
print(f"  {'intercept':>18s}: {clf.intercept_[0]:+.3f}")

conf_llm_fit = clf.predict_proba(Xf)[:, 1]
conf_llm_eval = clf.predict_proba(Xe)[:, 1]


def auc(y, p):
    order = np.argsort(p)
    y_s = y[order]
    n1, n0 = y_s.sum(), len(y_s) - y_s.sum()
    if n1 == 0 or n0 == 0:
        return float("nan")
    ranks = np.argsort(np.argsort(p)) + 1
    return (ranks[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)


print(f"\nAUC(exact) conf_llm — fit={auc(yf, conf_llm_fit):.3f}  eval={auc(ye, conf_llm_eval):.3f}")
print(f"AUC(exact) conf_regex (so sánh, đã có sẵn) — "
      f"fit={auc(yf, L2.conf_regex.to_numpy()[fit_idx]):.3f}  "
      f"eval={auc(ye, L2.conf_regex.to_numpy()[eval_idx]):.3f}")

# ── lưu model + toàn bộ bảng (kèm conf_llm, cll_split) để Pha 20c dùng lại, không fit lại ──
model_out = {
    "seed": SEED, "features": list(X_all.columns), "coef": coef,
    "intercept": float(clf.intercept_[0]),
    "n_fit": int(len(fit_idx)), "n_eval": int(len(eval_idx)),
    "auc_fit": float(auc(yf, conf_llm_fit)), "auc_eval": float(auc(ye, conf_llm_eval)),
}
(OUT / "pha20b_conf_llm_model.json").write_text(json.dumps(model_out, indent=2, ensure_ascii=False),
                                                  encoding="utf-8")

conf_llm_all = np.empty(len(L2))
conf_llm_all[fit_idx] = conf_llm_fit
conf_llm_all[eval_idx] = conf_llm_eval
L2["conf_llm"] = conf_llm_all

keep_cols = ["file_id", "domain", "gi", "pi", "li", "conf_regex", "conf_llm", "cll_split",
             "matched_rule", "need_review", "scs_nonempty", "has_auth_secret_v",
             "jump", "abs_jump", "mr_strong", "mr_empty", "reason_len", "reason_hedge", "reason_digit"]
L2[keep_cols].to_json(OUT / "pha20b_l2_with_conf.jsonl", orient="records", lines=True, force_ascii=False)
print(f"\n✅ pha2out/pha20b_conf_llm_model.json")
print(f"✅ pha2out/pha20b_l2_with_conf.jsonl  ({len(L2)} dòng, cột cll_split=fit/eval)")
