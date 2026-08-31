"""Render captured terminal output as an SVG that looks like a terminal."""
import re, sys, html

PALETTE = {
    30: "#6e7681", 31: "#ff7b72", 32: "#7ee787", 33: "#e3b341",
    34: "#79c0ff", 35: "#d2a8ff", 36: "#56d4dd", 37: "#c9d1d9",
    90: "#8b949e", 91: "#ffa198", 92: "#56d364", 93: "#e3b341",
    94: "#79c0ff", 95: "#d2a8ff", 96: "#56d4dd", 97: "#f0f6fc",
}
FG = "#c9d1d9"
PROMPT = "#7ee787"
COMMAND = "#f0f6fc"

CHAR_W = 8.4
LINE_H = 20.0
FONT = 14
PAD_X, PAD_TOP = 20.0, 52.0
BG, CHROME, BORDER = "#0d1117", "#161b22", "#30363d"

def runs(line):
    """(text, colour, bold) runs, splitting on SGR escapes."""
    out, colour, bold, pos = [], FG, False, 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", line):
        if m.start() > pos:
            out.append((line[pos:m.start()], colour, bold))
        for code in (int(c) for c in (m.group(1) or "0").split(";") if c != ""):
            if code == 0:
                colour, bold = FG, False
            elif code == 1:
                bold = True
            elif code in PALETTE:
                colour = PALETTE[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], colour, bold))
    return out

def clean(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    raw = raw.replace("\r", "").replace("\x04", "").replace("\x08", "")
    # script(1) echoes the end of input as a literal caret-D into the capture
    raw = re.sub(r"^\^D", "", raw)
    lines = raw.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    return lines

def render(panels, out_path):
    rows = []
    for command, path in panels:
        if rows:
            rows.append(None)
        rows.append(("prompt", command))
        for line in clean(path):
            rows.append(("out", line))

    width_cells = max(
        (len(re.sub(r"\x1b\[[0-9;]*m", "", text)) + (2 if kind == "prompt" else 0))
        for row in rows if row for kind, text in [row]
    )
    width = PAD_X * 2 + (width_cells + 2) * CHAR_W
    height = PAD_TOP + len(rows) * LINE_H + 18

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="{FONT}">',
        f'<rect width="{width:.0f}" height="{height:.0f}" rx="10" fill="{BG}" stroke="{BORDER}"/>',
        f'<path d="M0 10a10 10 0 0 1 10-10h{width - 20:.0f}a10 10 0 0 1 10 10v22H0z" fill="{CHROME}"/>',
        f'<line x1="0" y1="32" x2="{width:.0f}" y2="32" stroke="{BORDER}"/>',
        '<circle cx="20" cy="16" r="6" fill="#ff5f57"/>',
        '<circle cx="40" cy="16" r="6" fill="#febc2e"/>',
        '<circle cx="60" cy="16" r="6" fill="#28c840"/>',
        f'<text x="{width/2:.0f}" y="21" fill="#8b949e" font-size="12" text-anchor="middle">certreader</text>',
    ]

    y = PAD_TOP
    for row in rows:
        if row is None:
            y += LINE_H
            continue
        kind, text = row
        if kind == "prompt":
            svg.append(
                f'<text x="{PAD_X:.0f}" y="{y:.0f}" xml:space="preserve">'
                f'<tspan fill="{PROMPT}">$ </tspan>'
                f'<tspan fill="{COMMAND}">{html.escape(text)}</tspan></text>'
            )
        else:
            spans = []
            column = 0
            for run, colour, bold in runs(text):
                weight = ' font-weight="600"' if bold else ""
                # each run is placed on the character grid and told how wide to
                # be, so the columns line up whatever monospace font the reader
                # happens to have
                x = PAD_X + column * CHAR_W
                length = len(run) * CHAR_W
                spans.append(
                    f'<tspan x="{x:.1f}" textLength="{length:.1f}" lengthAdjust="spacing" '
                    f'fill="{colour}"{weight}>{html.escape(run)}</tspan>'
                )
                column += len(run)
            if not spans:
                spans = [f'<tspan x="{PAD_X:.0f}"> </tspan>']
            svg.append(f'<text y="{y:.0f}" xml:space="preserve">{"".join(spans)}</text>')
        y += LINE_H

    svg.append("</svg>")
    open(out_path, "w").write("\n".join(svg) + "\n")
    print(f"{out_path}: {width:.0f}x{height:.0f}, {len(rows)} rows")

render(
    [
        ("certreader -expiry google.com:443 github.com:443", sys.argv[1]),
        ("certreader request.csr", sys.argv[2]),
    ],
    sys.argv[3],
)
