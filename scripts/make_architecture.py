"""Figure 1: architecture — where each layer sits. Pure matplotlib, no network."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(11, 5.2)); ax.set_xlim(0, 11.2)
plt.rcParams["font.size"] = 11; ax.set_ylim(0, 5.2); ax.axis("off")

def box(x, y, w, h, text, fc, ec="#333", fs=11, bold=False, tc="#111"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, fontweight="bold" if bold else "normal", wrap=True)

def arrow(x1, y1, x2, y2, color="#333", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, color=color, lw=1.2, ls=ls))

# attacker sources (left)
box(0.2, 3.9, 1.9, 0.75, "Attacker's email\n→ Layla's inbox", "#fde2e1", "#9e2a2b")
box(0.2, 2.9, 1.9, 0.75, "Edited document\n(policy wiki, PDF)", "#fde2e1", "#9e2a2b")
box(0.2, 1.3, 1.9, 0.75, "Layla (user)\ntyped request", "#e3f2fd", "#335c67")
box(0.2, 0.3, 1.9, 0.75, "Company directory", "#e3f2fd", "#335c67")

# origin stamping
box(2.55, 2.75, 1.45, 2.05, "Origin stamp\nat entry\n\nEXTERNAL", "#fff4e0", "#e09f3e", fs=10.5)
box(2.55, 0.3, 1.45, 1.75, "Origin stamp\n\nUSER /\nDIRECTORY", "#fff4e0", "#e09f3e", fs=10.5)
arrow(2.1, 4.27, 2.55, 4.0); arrow(2.1, 3.27, 2.55, 3.4)
arrow(2.1, 1.67, 2.55, 1.4); arrow(2.1, 0.67, 2.55, 0.9)

# layer 1 + 2 on external text
box(4.4, 3.85, 1.6, 0.85, "① Sanitize\nhidden text → visible", "#e8f5e9", "#2a9d8f", fs=10.5)
box(4.4, 2.75, 1.6, 0.85, "② Detector\nrubric, 0.10, max-of-3\ncut the quoted span", "#e8f5e9", "#2a9d8f", fs=10)
arrow(4.0, 4.27, 4.4, 4.27); arrow(5.2, 3.85, 5.2, 3.6)

# agent
box(6.5, 1.6, 1.8, 2.3, "Agent\ngpt-oss-20b\n≤ 6 turns\n\nprompt never\nhardened", "#f5f5f5", "#555", fs=10.5)
arrow(6.0, 3.17, 6.5, 3.0)            # filtered external text
arrow(4.0, 1.5, 6.5, 2.1, color="#335c67")   # user + directory text, untouched
ax.text(5.0, 2.05, "user + directory text,\nread untouched", fontsize=9, color="#335c67", ha="center")

# layer 3 + 4 on the send
box(8.75, 2.45, 2.0, 1.1, "③ Provenance gate\nevery To/CC/BCC & URL\nmust trace to USER\nor DIRECTORY bytes", "#e8f5e9", "#2a9d8f", fs=10)
box(8.75, 1.0, 2.0, 0.9, "④ Human review\nsees exact email +\nlook-alike warning", "#e8f5e9", "#2a9d8f", fs=10)
arrow(8.3, 2.95, 8.75, 2.95)
arrow(9.75, 2.45, 9.75, 1.9)
box(8.75, 0.35, 2.0, 0.45, "Mail sink (no SMTP)", "#eeeeee", "#777", fs=10)
arrow(9.75, 1.0, 9.75, 0.8)

# provenance link
# origin tags travel along the bottom to the gate, bypassing the agent
ax.plot([3.3, 3.3, 10.95, 10.95], [0.3, 0.1, 0.1, 3.0], color="#e09f3e", ls="--", lw=1.2)
ax.add_patch(FancyArrowPatch((10.95, 3.0), (10.75, 3.0), arrowstyle="-|>", mutation_scale=12, color="#e09f3e", lw=1.2))
ax.text(6.0, 0.18, "origin tags → gate (the gate consults where bytes came from, never what they say)", fontsize=9.5, color="#b07a1e", ha="center")
ax.text(5.5, 5.0, "What the agent READS", fontsize=11.5, ha="center", color="#2a9d8f", fontweight="bold")
ax.text(9.75, 3.95, "What the agent SENDS", fontsize=11.5, ha="center", color="#2a9d8f", fontweight="bold")
ax.text(0.2, 4.95, "Attacker: no account, no chat access — only text", fontsize=10, color="#9e2a2b")
fig.tight_layout(); fig.savefig("results/fig_architecture.png", dpi=200, bbox_inches="tight"); print("ok")
