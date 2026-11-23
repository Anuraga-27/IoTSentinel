"""Draws program and output screenshots for the report from the real source
files and real captured output (docs/report/output/*.txt).

Run:  .venv\\Scripts\\python.exe docs\\report\\make_screenshots.py
"""

import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OUT = HERE / "figures"
FONT = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 26)
FONT_B = ImageFont.truetype(r"C:\Windows\Fonts\consolab.ttf", 26)
UI = ImageFont.truetype(r"C:\Windows\Fonts\segoeui.ttf", 24)
LH = 34       # line height
PAD = 28
BAR = 52      # title bar height

DARK = {"bg": (30, 30, 30), "bar": (45, 45, 48), "text": (212, 212, 212), "dim": (110, 118, 129),
        "kw": (86, 156, 214), "str": (206, 145, 120), "com": (106, 153, 85), "num": (181, 206, 168),
        "fn": (220, 220, 170), "key": (156, 220, 254)}
PY_KW = r"\b(?:def|class|return|if|elif|else|for|while|in|not|and|or|is|None|True|False|import|from|as|self|with|try|except|lambda|pass|continue|break|yield|del)\b"


def colour_runs(line, lang):
    """Split one line into (text, colour) runs with a small regex highlighter."""
    c = DARK
    if lang == "text":
        return [(line, c["text"])]
    comment = "#"
    pos = line.find(comment)
    in_str = False
    for k, ch in enumerate(line):
        if ch in "\"'":
            in_str = not in_str
        if ch == comment and not in_str:
            pos = k
            break
    else:
        pos = -1
    code, com = (line[:pos], line[pos:]) if pos >= 0 else (line, "")
    tokens = re.split(r"(\"[^\"]*\"|'[^']*'|" + PY_KW + r"|\b\d+(?:\.\d+)?\b|\w+(?=\()|^\s*[\w_]+(?=:))", code)
    runs = []
    for tok in tokens:
        if not tok:
            continue
        if tok[0] in "\"'":
            col = c["str"]
        elif lang == "py" and re.fullmatch(PY_KW, tok):
            col = c["kw"]
        elif re.fullmatch(r"\d+(?:\.\d+)?", tok):
            col = c["num"]
        elif lang == "py" and re.fullmatch(r"\w+", tok) and code.find(tok + "(") >= 0:
            col = c["fn"]
        elif lang == "yaml" and re.fullmatch(r"\s*[\w_]+", tok):
            col = c["key"]
        else:
            col = c["text"]
        runs.append((tok, col))
    if com:
        runs.append((com, c["com"]))
    return runs


def window(title, lines, lang, out_name, line_numbers=None, prompt=None, max_cols=100):
    c = DARK
    rows = []
    if prompt:
        rows.append(("prompt", prompt))
    for ln in lines:
        while len(ln) > max_cols:
            rows.append(("text", ln[:max_cols]))
            ln = "    " + ln[max_cols:]
        rows.append(("text", ln))
    gutter = 0
    if line_numbers:
        gutter = int(FONT.getlength("0000")) + 20
    cw = FONT.getlength("M")
    width = int(PAD * 2 + gutter + cw * min(max_cols, max(len(r[1]) for r in rows)))
    width = max(width, 900)
    height = BAR + PAD * 2 + LH * len(rows)
    img = Image.new("RGB", (width, height), c["bg"])
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, BAR], fill=c["bar"])
    d.text((PAD, BAR / 2), title, font=UI, fill=(200, 200, 200), anchor="lm")
    y = BAR + PAD
    n = line_numbers or 0
    for kind, text in rows:
        x = PAD
        if line_numbers:
            d.text((x, y), f"{n:>4}", font=FONT, fill=c["dim"])
            x += gutter
            n += 1
        if kind == "prompt":
            d.text((x, y), "PS D:\\IoTSentinel> ", font=FONT_B, fill=(97, 175, 239))
            x += FONT_B.getlength("PS D:\\IoTSentinel> ")
            d.text((x, y), text, font=FONT, fill=c["text"])
        else:
            for tok, col in colour_runs(text, lang):
                d.text((x, y), tok, font=FONT, fill=col)
                x += FONT.getlength(tok)
        y += LH
    img.save(OUT / out_name)
    print("wrote", out_name, img.size)


def code(title, rel, start, end, out_name, lang="py"):
    lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()[start - 1:end]
    window(f"{title}  —  {rel}", lines, lang, out_name, line_numbers=start)


def terminal(title, command, txt, out_name, keep=None, max_cols=100):
    lines = (HERE / "output" / txt).read_text(encoding="utf-8-sig").splitlines()
    if keep:
        lines = keep(lines)
    window(title, lines, "text", out_name, prompt=command, max_cols=max_cols)


if __name__ == "__main__":
    code("Detection settings", "rules/rules.yaml", 6, 31, "code_rules_yaml.png", lang="yaml")
    code("Rule engine: sliding-window checks", "src/iotsentinel/rule_engine.py", 196, 229, "code_rule_engine.png")
    code("ARP tracker: grace period and contention", "src/iotsentinel/rule_engine.py", 138, 157, "code_arp_tracker.png")
    code("Incident grouper", "src/iotsentinel/rule_engine.py", 260, 284, "code_incident_grouper.png")

    def short_tests(lines):
        out = []
        for ln in lines:
            m = re.match(r"(test_\w+) \(([\w.]+)\) \.\.\. (\w+)", ln)
            out.append(f"{m.group(1):<52} {m.group(2).split('.')[1]:<34} {m.group(3)}" if m else ln)
        return out

    terminal("Windows PowerShell — unit tests", ".venv\\Scripts\\python.exe -m unittest discover -s tests -v",
             "tests.txt", "out_tests.png", keep=short_tests, max_cols=94)
    terminal("Windows PowerShell — validation report", ".venv\\Scripts\\python.exe validation\\run_validation.py",
             "validation.txt", "out_validation.png", keep=lambda ls: [l for l in ls if not l.startswith("Note:")])
    terminal("Windows PowerShell — real packet captures", ".venv\\Scripts\\python.exe validation\\run_pcap_validation.py D:\\CIC\\pcap",
             "pcap.txt", "out_pcap.png", max_cols=104)
