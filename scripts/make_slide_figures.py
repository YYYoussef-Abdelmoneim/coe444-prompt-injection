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
    n_all = len({t for (t, cc) in by})     # payloads in the set, incl. ones whose retrieval missed under a condition
    for c in COND:
        items = [o for (t, cc), o in by.items() if cc == c]
        k = sum(1 for o in items if sum(x == "attack_success" for x in o) * 2 >= len(o) and any(x == "attack_success" for x in o))
        out[c] = (Rate(k, len(items)), n_all)
    return out

# ── Slide 4 main figure: attack success, 3 corpora × 4 conditions ──
fig, ax = plt.subplots(figsize=(13, 5.9))
w = 0.2
for j, (name, path) in enumerate(SWEEPS):
    rr = payload_rates(path)
    for i, c in enumerate(COND):
        rc, n_all = rr[c]
        x = j + (i - 1.5) * w; v = rc.value * 100; lo, hi = rc.wilson()
        ax.bar(x, max(v, 1.2), w * 0.92, color=COLOR[c], label=LABEL[c] if j == 0 else None)   # zero → thin visible stub
        ax.errorbar(x, v, yerr=[[(rc.value - lo) * 100], [(hi - rc.value) * 100]], fmt="none", ecolor=INK, capsize=3, lw=1.2)
        ax.text(x, max(v, 0) + (hi - rc.value) * 100 + 3, f"{rc.numerator}/{n_all}", ha="center", va="bottom", fontsize=19, color=GREEN if c == "D" else INK, fontweight="bold" if c == "D" else "normal")
ax.set_xticks(range(len(SWEEPS))); ax.set_xticklabels([s[0] for s in SWEEPS])
ax.set_ylabel("Attacks that succeeded (%)"); ax.set_ylim(0, 112); ax.set_yticks([0, 25, 50, 75, 100])
ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.17), frameon=False, handlelength=1.2, columnspacing=1.4)
for s in ("top", "right"): ax.spines[s].set_visible(False)
fig.text(0.99, 0.01, "Brackets: 95 % CI. A payload the agent never retrieved counts as not attempted, not as a success.", ha="right", fontsize=15, color="#555")
fig.tight_layout(); fig.savefig("results/slide_asr.png", dpi=200); plt.close(fig)

# ── Slide 3 figure: architecture — same structure as the report's Figure 1 (make_architecture.py),
#    bigger type for a projector. Origin stamps at entry; tags travel to the GATE, not to the output.
fig, ax = plt.subplots(figsize=(14, 6.2)); ax.set_xlim(0, 11.2); ax.set_ylim(0, 5.3); ax.axis("off")
def box(x, y, w, h, text, fc, ec, fs=15, bold=False, tc=INK):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.6))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, fontweight="bold" if bold else "normal", linespacing=1.15)
def arrow(x1, y1, x2, y2, color=INK, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=16, color=color, lw=1.8, ls=ls))
# sources (left)
box(0.2, 3.9, 1.9, 0.8, "Attacker's email\n→ Layla's inbox", "#fde2e1", RED, tc=RED)
box(0.2, 2.9, 1.9, 0.8, "Edited document\n(wiki, PDF)", "#fde2e1", RED, tc=RED)
box(0.2, 1.3, 1.9, 0.8, "Layla's typed\nrequest", "#e3f2fd", SLATE, tc=SLATE)
box(0.2, 0.3, 1.9, 0.8, "Company directory", "#e3f2fd", SLATE, tc=SLATE)
# origin stamps
box(2.55, 2.75, 1.45, 2.05, "Origin stamp\nat entry\n\nEXTERNAL", "#fff4e0", AMBER, fs=14, bold=True)
box(2.55, 0.3, 1.45, 1.8, "Origin stamp\n\nUSER /\nDIRECTORY", "#fff4e0", AMBER, fs=14, bold=True)
arrow(2.1, 4.3, 2.55, 4.05); arrow(2.1, 3.3, 2.55, 3.45)
arrow(2.1, 1.7, 2.55, 1.45); arrow(2.1, 0.7, 2.55, 0.95)
# layers 1-2 on external text
box(4.4, 3.85, 1.7, 0.85, "1  Sanitize\nhidden text → visible", "#e8f5e9", GREEN, fs=14)
box(4.4, 2.75, 1.7, 0.85, "2  Detector\ncuts the instruction", "#e8f5e9", GREEN, fs=14)
arrow(4.0, 4.27, 4.4, 4.27); arrow(5.25, 3.85, 5.25, 3.6)
# agent
box(6.6, 1.6, 1.8, 2.3, "Agent\n(gpt-oss-20b)\n\nprompt never\nhardened", "#f5f5f5", "#555", fs=14, bold=True)
arrow(6.1, 3.17, 6.6, 3.0)
arrow(4.0, 1.5, 6.6, 2.1, color=SLATE)
ax.text(5.15, 2.0, "user + directory text,\nread untouched", fontsize=12, color=SLATE, ha="center", style="italic")
# layers 3-4 on the send
box(8.85, 2.45, 2.1, 1.15, "3  Provenance gate\nevery address & link must\ntrace to USER or DIRECTORY", "#e8f5e9", GREEN, fs=13)
box(8.85, 1.0, 2.1, 0.95, "4  Human review\nsees what was removed\n+ security notice", "#e8f5e9", GREEN, fs=13)
arrow(8.4, 3.0, 8.85, 3.0); arrow(9.9, 2.45, 9.9, 1.95)
box(8.85, 0.3, 2.1, 0.5, "Sent", "#eeeeee", "#777", fs=14)
arrow(9.9, 1.0, 9.9, 0.8)
# origin tags travel along the bottom to the GATE, bypassing the agent
ax.plot([3.3, 3.3, 11.1, 11.1], [0.3, 0.08, 0.08, 3.0], color=AMBER, ls="--", lw=1.8)
ax.add_patch(FancyArrowPatch((11.1, 3.0), (10.95, 3.0), arrowstyle="-|>", mutation_scale=16, color=AMBER, lw=1.8))
ax.text(6.2, 0.16, "origin tags → gate: it asks where the bytes came from, never what they say", fontsize=13, color="#b07a1e", ha="center")
ax.text(5.25, 5.0, "What the agent READS", fontsize=17, ha="center", color=GREEN, fontweight="bold")
ax.text(9.9, 3.95, "What the agent SENDS", fontsize=17, ha="center", color=GREEN, fontweight="bold")
ax.text(0.2, 5.0, "Attacker: no account, no chat access — only text", fontsize=13, color=RED, style="italic")
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
