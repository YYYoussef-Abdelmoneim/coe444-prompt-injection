"""Slide-ready figures, drawn from logs only.

Static PNGs for the progress slides, in light mode. One house style: thin marks,
hairline solid grids, text in ink tokens (never the series colour), a legend for
two or more series. Colours follow the entity, in a fixed order validated for
colour-vision deficiency (dataviz skill, scripts/validate_palette.js): slot 1
blue for the LLM detector, slot 2 orange for the keyword baseline. Every figure
has a table twin in the markdown report next to it.
"""

from __future__ import annotations

from pathlib import Path

SURFACE = "#fcfcfb"
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
SERIES = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100")  # slots 1-4, fixed order


def _axes(title: str, subtitle: str, size=(7.2, 5.4)):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=size, dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(0.8)
    ax.grid(True, color=GRID, linewidth=0.6, linestyle="-")
    ax.set_axisbelow(True)
    ax.tick_params(colors=MUTED, labelsize=8.5, length=0)
    fig.text(0.06, 0.965, title, fontsize=12.5, fontweight="semibold", color=INK, va="top")
    fig.text(0.06, 0.915, subtitle, fontsize=8.8, color=INK_2, va="top")
    return fig, ax


def roc_figure(curves: list[dict], chosen: dict, out: Path, *, title: str, subtitle: str,
               target: tuple[float, float] | None = None) -> Path:
    """curves: [{label, points: [(fpr, tpr)], auc}]; chosen: {fpr, tpr, label}."""
    fig, ax = _axes(title, subtitle)
    ax.plot([0, 1], [0, 1], color=AXIS, linewidth=1, solid_capstyle="round", zorder=1)
    ax.text(0.62, 0.55, "chance", color=MUTED, fontsize=8, rotation=37)
    if target is not None:
        max_fpr, min_tpr = target
        ax.fill_between([0, max_fpr], min_tpr, 1, color=INK, alpha=0.05, linewidth=0, zorder=0)
        # Caption just outside the box's lower-right corner, clear of the curves
        # and of the chosen-point label above it.
        ax.text(max_fpr + 0.012, min_tpr, f"proposal target: FPR < {max_fpr:.0%}, FNR < {1 - min_tpr:.0%}",
                color=MUTED, fontsize=7.6, va="bottom")
    for i, c in enumerate(curves):
        # Operating points joined by straight segments, the convention the
        # trapezoid AUC assumes; a step would contradict the number in the legend.
        xs, ys = zip(*sorted(set(c["points"])))
        ax.plot(xs, ys, color=SERIES[i], linewidth=2, solid_joinstyle="round", solid_capstyle="round",
                label=f"{c['label']}, AUC {c['auc']:.2f}", zorder=3)
    ax.scatter([chosen["fpr"]], [chosen["tpr"]], s=64, color=SERIES[0], edgecolors=SURFACE,
               linewidths=2, zorder=4)
    ax.annotate(chosen["label"], (chosen["fpr"], chosen["tpr"]), xytext=(0.22, 0.9), textcoords="data",
                fontsize=8.2, color=INK, va="center",
                arrowprops={"arrowstyle": "-", "color": MUTED, "linewidth": 0.8, "shrinkA": 2, "shrinkB": 5})
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.04)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
    ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
    ax.set_xlabel("False positive rate: clean excerpts flagged", fontsize=9, color=INK_2, labelpad=8)
    ax.set_ylabel("True positive rate: poisoned excerpts caught", fontsize=9, color=INK_2, labelpad=8)
    legend = ax.legend(loc="lower right", frameon=False, fontsize=8.5)
    for text in legend.get_texts():
        text.set_color(INK)
    fig.subplots_adjust(left=0.12, right=0.96, top=0.84, bottom=0.12)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, facecolor=SURFACE)
    import matplotlib.pyplot as plt

    plt.close(fig)
    return out
