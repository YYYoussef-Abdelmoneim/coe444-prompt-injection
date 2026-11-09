"""Approximate slide renderer (no PowerPoint/LibreOffice): draws every shape of a .pptx with
matplotlib at true geometry — fills, text (with wrapping at the box width), pictures. Good enough
to catch overflow, overlap and unreadable sizes. Usage: python scripts/render_pptx.py deck.pptx outdir"""
import sys, io, textwrap
from pptx import Presentation
from pptx.util import Emu
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from PIL import Image

def emu_in(e): return e / 914400.0

def render(path, outdir):
    p = Presentation(path); W, H = emu_in(p.slide_width), emu_in(p.slide_height)
    import os; os.makedirs(outdir, exist_ok=True)
    for i, s in enumerate(p.slides, 1):
        fig = plt.figure(figsize=(W, H), dpi=110); ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(H, 0); ax.axis("off")
        for sh in s.shapes:
            l, t, w, h = map(emu_in, (sh.left, sh.top, sh.width, sh.height))
            # fill
            try:
                if sh.fill.type == 1:  # solid
                    c = sh.fill.fore_color.rgb; ax.add_patch(Rectangle((l, t), w, h, fc=f"#{c}", ec="none", alpha=0.95))
            except Exception:
                pass
            if sh.shape_type == 13:  # picture
                img = Image.open(io.BytesIO(sh.image.blob)); ax.imshow(img, extent=(l, l + w, t + h, t), aspect="auto")
                ax.add_patch(Rectangle((l, t), w, h, fc="none", ec="#bbb", lw=0.5)); continue
            if not sh.has_text_frame: continue
            y = t + 0.08
            for para in sh.text_frame.paragraphs:
                txt = "".join(r.text for r in para.runs)
                if not txt.strip(): y += 0.12; continue
                r0 = para.runs[0]; size = (r0.font.size.pt if r0.font.size else 12)
                color = "#222"
                try:
                    if r0.font.color and r0.font.color.type is not None and r0.font.color.rgb is not None: color = f"#{r0.font.color.rgb}"
                except Exception: pass
                indent = 0.25 * (para.level or 0)
                chars_per_in = 72 / (size * 0.52)       # ~0.52 em average glyph width
                wrapped = textwrap.wrap(txt, width=max(8, int((w - 0.2 - indent) * chars_per_in)))
                for line in wrapped:
                    ax.text(l + 0.1 + indent, y, line, fontsize=size * 0.86, color=color, va="top", ha="left",
                            fontweight="bold" if r0.font.bold else "normal", family="DejaVu Sans")
                    y += size / 72 * 1.22
                y += 0.04
            # text overflow marker
            if y > t + h + 0.05:
                ax.add_patch(Rectangle((l, t), w, h, fc="none", ec="red", lw=2, ls="--"))
                ax.text(l + w - 0.1, t + h, f"OVERFLOW +{y - (t + h):.2f}in", color="red", fontsize=8, ha="right", va="bottom")
        fig.savefig(f"{outdir}/slide{i}.png"); plt.close(fig)
    print("rendered", len(p.slides), "slides to", outdir)

if __name__ == "__main__":
    render(sys.argv[1], sys.argv[2])
