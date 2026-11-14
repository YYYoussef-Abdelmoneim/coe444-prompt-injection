"""Presentation-scale figures: the same data as the report figures, drawn for a projector.
Big type (>=16 pt), one message per figure, no sub-plots. Writes results/slide_*.png."""
import json, collections, sys
sys.path.insert(0, ".")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from evaluation.metrics import Rate

plt.rcParams.update({"font.family": "Times New Roman", "font.size": 22, "axes.titlesize": 22, "axes.labelsize": 22,
                     "xtick.labelsize": 22, "ytick.labelsize": 20, "legend.fontsize": 21})
RED, AMBER, SLATE, GREEN, INK = "#9e2a2b", "#e09f3e", "#335c67", "#2a9d8f", "#1f2937"

SWEEPS = [("Dev\n10 attacks", "logs/scored-live-20261108T213725Z-scorer-v2.jsonl"),
          ("18 new\nfamilies", "logs/scored-live-20261108T211359Z-scorer-v2.jsonl"),
          ("Sealed test\n13 attacks", "logs/scored-live-20261109T072833Z.jsonl")]
COND = ["A", "B", "C", "D"]; LABEL = {"A": "No defense", "B": "Detection only", "C": "Gate only", "D": "Both"}
COLOR = {"A": RED, "B": AMBER, "C": SLATE, "D": GREEN}

def payload_rates(path):
    by = collections.defaultdict(list)
    for l in open(path):
        s = json.loads(l)
        if s["task_id"].startswith("PI") and s["outcome"] != "retrieval_miss":
            by[(s["task_id"], s["condition"])].append(s["outcome"])
    out = {}
    for c in COND:
        items = [o for (t, cc), o in by.items() if cc == c]
        k = sum(1 for o in items if sum(x == "attack_success" for x in o) * 2 >= len(o) and any(x == "attack_success" for x in o))
        out[c] = Rate(k, len(items))
    return out

# ── Slide 4 main figure: attack success, 3 corpora × 4 conditions ──
fig, ax = plt.subplots(figsize=(13, 5.9))
w = 0.2
for j, (name, path) in enumerate(SWEEPS):
    r = payload_rates(path)
    for i, c in enumerate(COND):
        x = j + (i - 1.5) * w; v = r[c].value * 100; lo, hi = r[c].wilson()
        ax.bar(x, max(v, 1.2), w * 0.92, color=COLOR[c], label=LABEL[c] if j == 0 else None)   # zero → thin visible stub
        ax.errorbar(x, v, yerr=[[(r[c].value - lo) * 100], [(hi - r[c].value) * 100]], fmt="none", ecolor=INK, capsize=3, lw=1.2)
        ax.text(x, max(v, 0) + (hi - r[c].value) * 100 + 3, f"{r[c].numerator}/{r[c].denominator}", ha="center", va="bottom", fontsize=19, color=GREEN if c == "D" else INK, fontweight="bold" if c == "D" else "normal")
ax.set_xticks(range(len(SWEEPS))); ax.set_xticklabels([s[0] for s in SWEEPS])
ax.set_ylabel("Attacks that succeeded (%)"); ax.set_ylim(0, 112); ax.set_yticks([0, 25, 50, 75, 100])
ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.17), frameon=False, handlelength=1.2, columnspacing=1.4)
for s in ("top", "right"): ax.spines[s].set_visible(False)
fig.text(0.99, 0.01, "Brackets: 95 % confidence intervals", ha="right", fontsize=16, color="#555")
fig.tight_layout(); fig.savefig("results/slide_asr.png", dpi=200); plt.close(fig)

# ── Slide 3 figure: architecture, big type ──
fig, ax = plt.subplots(figsize=(13.5, 5.4)); ax.set_xlim(0, 12.5); ax.set_ylim(0, 5.4); ax.axis("off")
def box(x, y, w, h, text, fc, ec, fs=17, bold=False, tc=INK):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1", fc=fc, ec=ec, lw=1.6))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, fontweight="bold" if bold else "normal", linespacing=1.15)
def arrow(x1, y1, x2, y2, color=INK, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=18, color=color, lw=1.8, ls=ls))
box(0.2, 3.6, 2.3, 1.1, "Attacker's email\nor edited document", "#fde2e1", RED)
box(0.2, 1.0, 2.3, 1.1, "Layla's request\n+ company directory", "#e3f2fd", SLATE)
box(3.1, 3.6, 2.0, 1.1, "① Sanitize\nhidden text → visible", "#e8f5e9", GREEN, fs=16)
box(5.6, 3.6, 2.0, 1.1, "② Detector\ncuts the instruction", "#e8f5e9", GREEN, fs=16)
box(8.1, 2.2, 1.8, 1.4, "Agent\n(gpt-oss-20b)", "#f3f4f6", "#555", fs=17, bold=True)
box(10.4, 3.4, 1.9, 1.1, "③ Gate\nrecipients & links\nmust trace to you", "#e8f5e9", GREEN, fs=15)
box(10.4, 1.9, 1.9, 1.1, "④ Human review\n+ security notice", "#e8f5e9", GREEN, fs=15)
box(10.4, 0.5, 1.9, 0.8, "Sent", "#f3f4f6", "#555", fs=16)
arrow(2.5, 4.15, 3.1, 4.15); arrow(5.1, 4.15, 5.6, 4.15); arrow(7.6, 4.15, 8.1, 3.4)
arrow(2.5, 1.55, 8.1, 2.6, color=SLATE)
arrow(9.9, 2.9, 10.4, 3.6); arrow(11.35, 3.4, 11.35, 3.0); arrow(11.35, 1.9, 11.35, 1.3)
ax.plot([1.35, 1.35, 11.35], [1.0, 0.25, 0.25], color=AMBER, ls="--", lw=1.8); arrow(11.35, 0.25, 11.35, 0.5, color=AMBER)
ax.text(6.3, 0.45, "origin tags: where did these bytes come from?", fontsize=15, color="#b07a1e", ha="center")
ax.text(5.6, 5.1, "What the agent reads", fontsize=19, ha="center", color=GREEN, fontweight="bold")
ax.text(11.35, 4.85, "What it sends", fontsize=19, ha="center", color=GREEN, fontweight="bold")
ax.text(1.35, 3.15, "untrusted", fontsize=14, ha="center", color=RED, style="italic")
ax.text(1.35, 0.6, "trusted", fontsize=14, ha="center", color=SLATE, style="italic")
fig.tight_layout(); fig.savefig("results/slide_architecture.png", dpi=200, bbox_inches="tight"); plt.close(fig)

# ── Slide 2 figure: the attack in one picture ──
fig, ax = plt.subplots(figsize=(12, 3.6)); ax.set_xlim(0, 12); ax.set_ylim(0, 3.6); ax.axis("off")
box(0.3, 1.0, 2.6, 1.6, "Attacker\nsends one email", "#fde2e1", RED, fs=18)
box(4.1, 1.0, 3.4, 1.6, "Assistant reads the inbox\nfor Layla", "#f3f4f6", "#555", fs=18)
box(8.9, 1.0, 2.8, 1.6, "Attacker is BCC'd\non Layla's reply", "#fde2e1", RED, fs=18)
arrow(2.9, 1.8, 4.1, 1.8); arrow(7.5, 1.8, 8.9, 1.8)
ax.text(5.8, 0.35, "No account. No password. No click. Just text the assistant will read.  (EchoLeak, CVE-2025-32711, 2025)", fontsize=16, ha="center", color="#444", style="italic")
fig.tight_layout(); fig.savefig("results/slide_attack.png", dpi=200, bbox_inches="tight"); plt.close(fig)
print("ok")
