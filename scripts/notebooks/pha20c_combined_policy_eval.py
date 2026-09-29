# %% [markdown]
# # Pha 20c — Đánh giá policy kết hợp `conf_llm vs conf_regex` (+ guardrail Pha 15)
#
# Luật mới (Policy D), theo đúng yêu cầu: LLM chỉ được ĐỀ XUẤT escalate (không hạ mức — vẫn giữ
# kỷ luật escalate-only). Đề xuất escalate chỉ được CHẤP NHẬN khi `conf_llm >= conf_regex` của
# chính file đó — nếu `conf_llm < conf_regex`, giữ nguyên nhãn regex (engine tự tin hơn LLM).
# Sau đó áp toàn bộ guardrail Pha 15 (cap +1 bậc, matched_rule gate cho CONF->RES, need_review
# ->human) lên KẾT QUẢ đã qua cổng conf_llm.
#
# Đánh giá CHỈ trên nửa `eval` (744/1.487 file) của `pha20b_l2_with_conf.jsonl` — nửa `fit` đã
# dùng để fit `conf_llm` ở Pha 20b, không được đụng lại ở đây (tránh leakage). So sánh lại cả
# Policy A/B/C (Pha 15) TRÊN CÙNG nửa `eval` này để công bằng (Pha 15 gốc đo trên toàn bộ 1.487,
# không so sánh trực tiếp được).

# %%
from __future__ import annotations
import json, pathlib
import numpy as np, pandas as pd

OUT = pathlib.Path("pha2out")
LVL = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
LVL_IDX = {l: i for i, l in enumerate(LVL)}
STRONG_RULES = {"auth_secret", "special_category", "legal_investigation", "ma_strategy"}

L2 = pd.read_json(OUT / "pha20b_l2_with_conf.jsonl", lines=True)
ev = L2[L2.cll_split == "eval"].copy().reset_index(drop=True)
print(f"Nửa eval (out-of-sample cho conf_llm): {len(ev)} file")

gi = ev.gi.to_numpy()
pi = ev.pi.to_numpy()
li = ev.li.to_numpy()
conf_regex = ev.conf_regex.to_numpy()
conf_llm = ev.conf_llm.to_numpy()
mr = ev.matched_rule.fillna("").to_numpy()
nr = ev.need_review.to_numpy()
engine_evidence = (ev.scs_nonempty.to_numpy()) | (ev.has_auth_secret_v.to_numpy())
is_confres = (pi == LVL_IDX["CONFIDENTIAL"]) & (li == LVL_IDX["RESTRICTED"])
strong_rule = np.array([m in STRONG_RULES for m in mr])
gate_pass = strong_rule & engine_evidence


def metrics(final):
    acc = float((final == gi).mean())
    over = float((final > gi).mean())
    under = float((final < gi).mean())
    eu = pi < gi
    leak_recall = float((final[eu] >= gi[eu]).mean()) if eu.sum() else float("nan")
    by_level = {}
    for lvl_name, lvl_i in LVL_IDX.items():
        m = eu & (gi == lvl_i)
        if m.sum():
            by_level[lvl_name] = {"n": int(m.sum()), "leak_recall": float((final[m] >= gi[m]).mean())}
    return dict(accuracy=acc, over=over, under=under, leak_recall_global=leak_recall,
                leak_recall_by_level=by_level)


def apply_guardrail_134(esc, tag=None):
    """Guardrail (1)+(3)+(4) Pha 15, áp lên vector `esc` đã escalate (bất kể theo policy nào)."""
    review_flag = is_confres & (nr == True)  # noqa: E712
    block_confres = is_confres & (~review_flag) & (~gate_pass)
    out = esc.astype(float).copy()
    out = np.where(review_flag, pi.astype(float), out)
    out = np.where(block_confres, float(LVL_IDX["CONFIDENTIAL"]), out)
    return out.astype(int), review_flag


# ── Policy A: baseline escalate-only (max(engine, llm)) — mốc Pha 12/15 ──
finalA = np.maximum(pi, li)

# ── Policy B: + cap +1 bậc ──
finalB = np.minimum(finalA, pi + 1)

# ── Policy C: + guardrail 1+3+4 (Pha 15, nguyên bản) ──
finalC, reviewC = apply_guardrail_134(finalB)

# ── Policy D (MỚI): chỉ chấp nhận escalate của LLM khi conf_llm >= conf_regex, + cap+1
#     + guardrail 1+3+4 ──
accept_llm = (li > pi) & (conf_llm >= conf_regex)
escD = np.where(accept_llm, li, pi)
escD = np.minimum(escD, pi + 1)  # cap +1 (an toàn kép — abs_jump đã là feature mạnh nhất trong conf_llm)
finalD, reviewD = apply_guardrail_134(escD)

metA, metB, metC, metD = metrics(finalA), metrics(finalB), metrics(finalC), metrics(finalD)

print("\n" + "=" * 100)
print(f"SO SÁNH POLICY — CHỈ trên nửa `eval` out-of-sample ({len(ev)} file, route conf_regex<0.95)")
print("=" * 100)
rows = [
    ("A. baseline escalate-only (max(engine,llm))", metA, None),
    ("B. + cap +1 bậc", metB, None),
    ("C. + guardrail Pha15 (matched_rule gate + need_review->human)", metC, reviewC),
    ("D. MỚI: chỉ nhận escalate khi conf_llm>=conf_regex + cap+1 + guardrail Pha15", metD, reviewD),
]
for name, met, rv in rows:
    rv_s = f"  need_review%={rv.mean():.1%}" if rv is not None else ""
    print(f"\n[{name}]")
    print(f"  accuracy={met['accuracy']:.1%}  over={met['over']:.1%}  under={met['under']:.1%}  "
          f"leak_recall_global={met['leak_recall_global']:.3f}{rv_s}")
    print(f"  leak_recall theo mức: {json.dumps(met['leak_recall_by_level'], ensure_ascii=False)}")

n_accept = int(accept_llm.sum())
n_proposed_up = int((li > pi).sum())
print(f"\nPolicy D: LLM đề xuất escalate {n_proposed_up}/{len(ev)} file "
      f"({n_proposed_up/len(ev):.1%}); được CHẤP NHẬN (conf_llm>=conf_regex): {n_accept} "
      f"({n_accept/max(n_proposed_up,1):.1%} trong số đề xuất)")

# ── Ước lượng TỔNG pipeline (Layer 1 cố định theo Pha 12/15, Layer 2 = rate đo được ở trên) ──
# Layer 1 (regexing, conf_regex>=0.95): 2.294 file, đúng 85,9% / over 12,9% / under 1,2% (Pha 12 §3)
# — không đổi bởi bất kỳ policy Lớp 2 nào (không đụng threshold/engine).
L1_N, L1_ACC, L1_OVER, L1_UNDER = 2294, 0.859, 0.129, 0.012
L2_N_FULL = 1487


def total_pipeline(met):
    acc = (L1_N * L1_ACC + L2_N_FULL * met["accuracy"]) / (L1_N + L2_N_FULL)
    over = (L1_N * L1_OVER + L2_N_FULL * met["over"]) / (L1_N + L2_N_FULL)
    under = (L1_N * L1_UNDER + L2_N_FULL * met["under"]) / (L1_N + L2_N_FULL)
    return acc, over, under


print("\n" + "=" * 100)
print("ƯỚC LƯỢNG TỔNG PIPELINE (Layer1 cố định 2.294 file @ Pha12 + Layer2 suy từ rate đo ở nửa eval)")
print("=" * 100)
for name, met, _ in rows:
    acc, over, under = total_pipeline(met)
    print(f"  {name:<70s} acc={acc:.1%}  over={over:.1%}  under={under:.1%}")

out = {
    "n_eval": int(len(ev)),
    "policies": {
        "A_baseline": metA, "B_cap1": metB, "C_guardrail_pha15": metC,
        "D_conf_llm_gate": metD,
    },
    "policy_D_accept_stats": {
        "n_llm_proposed_escalate": n_proposed_up, "n_accepted": n_accept,
    },
    "total_pipeline_estimate": {
        name.split(".")[0]: dict(zip(["acc", "over", "under"], total_pipeline(met)))
        for name, met, _ in rows
    },
}
(OUT / "pha20c_combined_result.json").write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                                    encoding="utf-8")
print("\n✅ pha2out/pha20c_combined_result.json")
