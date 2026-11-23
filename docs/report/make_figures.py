"""Draws the report's design diagrams into docs/report/figures/.

Run:  .venv\\Scripts\\python.exe docs\\report\\make_figures.py
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(exist_ok=True)

INK = "#1f2933"
LINE = "#52606d"
FILL = {
    "input": "#e3f2fd", "process": "#e8f5e9", "store": "#fff8e1",
    "output": "#fce4ec", "decision": "#ede7f6", "attack": "#ffebee", "config": "#f3e5f5",
}
EDGE = {
    "input": "#1565c0", "process": "#2e7d32", "store": "#b7791f",
    "output": "#ad1457", "decision": "#5e35b1", "attack": "#c62828", "config": "#7b1fa2",
}


def box(ax, x, y, w, h, text, kind="process", size=9, bold_first=True):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=FILL[kind], ec=EDGE[kind], lw=1.4))
    lines = text.split("\n")
    if bold_first and len(lines) > 1:
        ax.text(x, y + h * 0.14, lines[0], ha="center", va="center",
                fontsize=size, fontweight="bold", color=INK)
        ax.text(x, y - h * 0.18, "\n".join(lines[1:]), ha="center", va="center",
                fontsize=size - 1.5, color=INK)
    else:
        ax.text(x, y, text, ha="center", va="center", fontsize=size,
                fontweight="bold" if bold_first else "normal", color=INK)


def diamond(ax, x, y, w, h, text, size=8.5):
    ax.add_patch(Polygon([(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)],
                         closed=True, fc=FILL["decision"], ec=EDGE["decision"], lw=1.4))
    ax.text(x, y, text, ha="center", va="center", fontsize=size, color=INK)


def arrow(ax, p, q, label=None, style="-|>", dashed=False, lpos=0.5, loff=(0, 0.12), rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=12, lw=1.3,
                                 color=LINE, linestyle="--" if dashed else "-",
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=2, shrinkB=2))
    if label:
        mx = p[0] + (q[0] - p[0]) * lpos + loff[0]
        my = p[1] + (q[1] - p[1]) * lpos + loff[1]
        ax.text(mx, my, label, ha="center", va="center", fontsize=7.5, color=LINE,
                bbox=dict(fc="white", ec="none", pad=0.6))


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


def save(fig, name):
    fig.savefig(OUT / name, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", OUT / name)


def architecture():
    fig, ax = canvas(11, 6.2)
    bands = [(5.2, "TRAFFIC SOURCES"), (3.1, "PROCESSING"), (1.0, "OUTPUT")]
    for y, label in bands:
        ax.add_patch(FancyBboxPatch((0.15, y - 0.85), 10.7, 1.7,
                                    boxstyle="round,pad=0.02,rounding_size=0.1",
                                    fc="#fafafa", ec="#d9dee3", lw=1))
        ax.text(0.35, y + 0.62, label, fontsize=8, color=LINE, fontweight="bold")

    box(ax, 2.6, 5.15, 2.6, 1.0, "Device simulator\n6 virtual IoT devices", "input")
    box(ax, 5.5, 5.15, 2.6, 1.0, "Attack simulator\n5 attacks, loud + slow", "attack")
    box(ax, 8.4, 5.15, 2.6, 1.0, "CIC IoT 2023\nCSV + PCAP samples", "input")

    box(ax, 1.9, 3.05, 2.2, 1.0, "Flow collector\nvalidate, drop bad", "process")
    box(ax, 4.75, 3.05, 2.5, 1.0, "Rule engine\n5 sliding-window rules", "process")
    box(ax, 7.6, 3.05, 2.3, 1.0, "Incident grouper\nmerge + severity", "process")
    box(ax, 9.95, 3.05, 1.5, 0.8, "rules.yaml\nthresholds", "config", size=8)

    box(ax, 3.4, 0.95, 2.8, 1.0, "SQLite alert store\nevery incident saved", "store")
    box(ax, 7.4, 0.95, 3.0, 1.0, "Streamlit dashboard\nstatus, traffic, alert log", "output")

    arrow(ax, (2.6, 4.65), (1.9, 3.55), "traffic records", loff=(-0.45, 0))
    arrow(ax, (5.5, 4.65), (2.3, 3.55), dashed=True)
    arrow(ax, (8.4, 4.65), (2.6, 3.55))
    arrow(ax, (3.0, 3.05), (3.5, 3.05))
    arrow(ax, (6.0, 3.05), (6.45, 3.05))
    arrow(ax, (9.95, 3.45), (5.6, 3.55), "thresholds", dashed=True, rad=0.18, loff=(0.6, 0.32))
    arrow(ax, (7.2, 2.55), (3.9, 1.45), "upsert", lpos=0.45, loff=(0, 0.15))
    arrow(ax, (7.6, 2.55), (7.4, 1.45), "live status")
    arrow(ax, (4.8, 0.95), (5.9, 0.95), "alert log")
    save(fig, "fig_architecture.png")


def data_flow():
    """Data flow from traffic sources through each rule to storage and display."""
    fig, ax = canvas(14.2, 5.0)
    box(ax, 1.15, 4.1, 1.9, 0.75, "Device simulator\nnormal traffic", "input", size=8.5)
    box(ax, 1.15, 2.5, 1.9, 0.75, "Attack simulator\n5 attacks", "attack", size=8.5)
    box(ax, 1.15, 0.9, 1.9, 0.75, "CIC IoT 2023\npacket captures", "input", size=8.5)
    box(ax, 3.75, 2.5, 1.8, 0.9, "Flow collector\ndrop malformed", "process", size=8.5)
    diamond(ax, 6.0, 2.5, 2.0, 1.3, "Route by\nevent type", size=8.5)
    box(ax, 9.3, 4.3, 2.0, 0.7, "Flooding + port scan\ncounters", "process", size=8)
    box(ax, 9.3, 3.1, 2.0, 0.7, "Brute-force\ncounter", "process", size=8)
    box(ax, 9.3, 1.9, 2.0, 0.7, "ARP tracker\ngrace period", "process", size=8)
    box(ax, 9.3, 0.7, 2.0, 0.7, "Botnet\ndistinct hosts", "process", size=8)
    box(ax, 11.6, 2.5, 1.6, 0.9, "Incident grouper\nmerge, severity", "process", size=8)
    box(ax, 13.4, 3.4, 1.4, 0.75, "SQLite\nalert store", "store", size=8)
    box(ax, 13.4, 1.6, 1.4, 0.75, "Dashboard\nlive status", "output", size=8)

    for y in (4.1, 2.5, 0.9):
        arrow(ax, (2.1, y), (2.85, 2.5))
    arrow(ax, (4.65, 2.5), (5.0, 2.5))
    for y, label in ((4.3, "packet"), (3.1, "login_failed"), (1.9, "arp_announce"), (0.7, "connect")):
        arrow(ax, (7.0, 2.5), (8.3, y))
        ax.text(7.75, 2.5 + (y - 2.5) * 0.58 + 0.13, label, fontsize=7.5, color=LINE, ha="center",
                bbox=dict(fc="white", ec="none", pad=0.5))
        arrow(ax, (10.3, y), (10.8, 2.5))
    arrow(ax, (12.4, 2.75), (12.7, 3.4))
    arrow(ax, (12.4, 2.25), (12.7, 1.6))
    save(fig, "fig_data_flow.png")


def processing_flowchart():
    fig, ax = canvas(8.6, 11.2)
    cx = 3.6
    box(ax, cx, 10.6, 3.0, 0.6, "Start: traffic record arrives", "input", bold_first=False)
    diamond(ax, cx, 9.55, 3.0, 1.0, "All fields present\nand port 0-65535?")
    box(ax, 7.2, 9.55, 2.0, 0.6, "Drop record,\ncount as dropped", "attack", size=8, bold_first=False)
    diamond(ax, cx, 8.1, 3.0, 1.0, "Which event?")
    box(ax, 0.9, 6.7, 1.6, 0.9, "packet\nflood + scan\ncounters", "process", size=8)
    box(ax, 2.7, 6.7, 1.6, 0.9, "login_failed\nbrute-force\ncounter", "process", size=8)
    box(ax, 4.5, 6.7, 1.6, 0.9, "arp_announce\nARP tracker\n(grace period)", "process", size=8)
    box(ax, 6.3, 6.7, 1.6, 0.9, "connect\nbotnet distinct\nhost counter", "process", size=8)
    box(ax, cx, 5.45, 4.6, 0.6, "Slide window: evict entries older than window_seconds",
        "process", size=8, bold_first=False)
    diamond(ax, cx, 4.35, 3.2, 1.0, "Count > threshold?\n(or ARP contention)")
    box(ax, 7.3, 4.35, 1.6, 0.6, "No alert", "process", size=8, bold_first=False)
    box(ax, cx, 3.25, 3.4, 0.6, "Raise violation (rule, source, target, value)",
        "decision", size=8, bold_first=False)
    diamond(ax, cx, 2.15, 3.4, 1.0, "Same rule/source/target\nseen within 60 s?")
    box(ax, 0.95, 1.0, 1.8, 0.8, "New incident\nbase severity", "store", size=8)
    box(ax, 6.25, 1.0, 1.9, 0.8, "Update incident\ncount++, escalate", "store", size=8)
    box(ax, cx, 0.3, 4.0, 0.5, "Save to SQLite, update dashboard", "output", size=8, bold_first=False)

    arrow(ax, (cx, 10.3), (cx, 10.05))
    arrow(ax, (cx + 1.5, 9.55), (6.2, 9.55), "no", loff=(0, 0.15))
    arrow(ax, (cx, 9.05), (cx, 8.6), "yes", loff=(0.25, 0))
    for x in (0.9, 2.7, 4.5, 6.3):
        arrow(ax, (cx, 7.6), (x, 7.15))
        arrow(ax, (x, 6.25), (cx, 5.75))
    arrow(ax, (cx, 5.15), (cx, 4.85))
    arrow(ax, (cx + 1.6, 4.35), (6.5, 4.35), "no", loff=(0, 0.15))
    arrow(ax, (cx, 3.85), (cx, 3.55), "yes", loff=(0.25, 0))
    arrow(ax, (cx, 2.95), (cx, 2.65))
    arrow(ax, (cx - 1.7, 2.15), (0.95, 1.4), "no", loff=(-0.2, 0.15))
    arrow(ax, (cx + 1.7, 2.15), (6.25, 1.4), "yes", loff=(0.2, 0.15))
    arrow(ax, (0.95, 0.6), (cx - 2.0, 0.3))
    arrow(ax, (6.25, 0.6), (cx + 2.0, 0.3))
    save(fig, "fig_processing_flowchart.png")


def arp_flowchart():
    fig, ax = canvas(9.4, 7.6)
    ax.set_ylim(-0.2, 7.6)
    ax.text(0.15, 2.0, "no: same MAC,\nnothing to do", fontsize=7.5, color=LINE)
    box(ax, 4.7, 7.15, 3.4, 0.55, "ARP announce: IP X claims MAC M", "input", size=8.5, bold_first=False)
    diamond(ax, 4.7, 6.2, 2.6, 0.9, "(X, M) on\nwhitelist?", size=8)
    box(ax, 8.2, 6.2, 1.8, 0.65, "Accept binding,\nno alert", "process", size=8, bold_first=False)
    diamond(ax, 4.7, 5.0, 2.6, 0.9, "X seen\nbefore?", size=8)
    box(ax, 1.2, 5.0, 1.8, 0.65, "Record X = M\n(first sighting)", "process", size=8, bold_first=False)
    diamond(ax, 4.7, 3.8, 2.6, 0.9, "Change already\npending for X?", size=8)
    diamond(ax, 1.6, 2.6, 2.4, 0.9, "M differs from\ncurrent MAC?", size=8)
    box(ax, 1.6, 1.25, 2.4, 0.75, "Open grace window:\npending = M, no alert", "decision", size=8, bold_first=False)
    diamond(ax, 6.2, 2.6, 2.4, 0.9, "M = pending\nMAC?", size=8)
    box(ax, 8.4, 1.25, 1.8, 0.75, "Grace over?\nthen accept M", "process", size=8, bold_first=False)
    diamond(ax, 5.0, 1.25, 2.2, 0.9, "Inside grace\nwindow?", size=8)
    box(ax, 3.5, 0.2, 2.6, 0.5, "CRITICAL alert: contention", "attack", size=8, bold_first=False)
    box(ax, 6.7, 0.2, 2.4, 0.5, "Settle old, track M", "process", size=8, bold_first=False)

    arrow(ax, (4.7, 6.87), (4.7, 6.65))
    arrow(ax, (6.0, 6.2), (7.3, 6.2), "yes", loff=(0, 0.13))
    arrow(ax, (4.7, 5.75), (4.7, 5.45), "no", loff=(0.22, 0))
    arrow(ax, (3.4, 5.0), (2.1, 5.0), "no", loff=(0, 0.13))
    arrow(ax, (4.7, 4.55), (4.7, 4.25), "yes", loff=(0.25, 0))
    arrow(ax, (3.4, 3.8), (1.6, 3.05), "no", loff=(-0.2, 0.15))
    arrow(ax, (6.0, 3.8), (6.2, 3.05), "yes", loff=(0.3, 0.05))
    arrow(ax, (1.6, 2.15), (1.6, 1.63), "yes", loff=(0.25, 0))
    arrow(ax, (7.4, 2.6), (8.4, 1.63), "yes", loff=(0.25, 0.1))
    arrow(ax, (6.2, 2.15), (5.0, 1.7), "no", loff=(-0.2, 0.1))
    arrow(ax, (4.0, 1.0), (3.5, 0.45), "yes", loff=(-0.25, 0.05))
    arrow(ax, (6.0, 1.0), (6.7, 0.45), "no", loff=(0.25, 0.05))
    save(fig, "fig_arp_flowchart.png")


if __name__ == "__main__":
    architecture()
    data_flow()
    processing_flowchart()
    arp_flowchart()
