# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Builds the documentation site source from README.md and docs/.

    python3 riddix/scripts/docs_site.py <out dir> [--baseurl /ulrmm]

README.md stays the only source: every "## " section becomes a page,
grouped in the navigation by GROUPS, plus the showcase (docs/SHOWCASE.md)
and the versioning notes. The home page is built from the README intro,
"What it does" and "Showcase". Links between sections point to the pages,
links to other repository files to GitHub. The pages workflow builds the
result with Jekyll and the just-the-docs theme; docs/pages holds its config
and the theme overrides (layout, colours, icons) and is copied as is."""

import html
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = "https://github.com/RiDDiX/ulrmm/blob/main/"
# navigation groups in order; a section that is not listed lands in "More"
GROUPS = {
    "Overview": [
        "What it does",
        "Showcase",
        "Architecture",
        "Repositories",
        "Versions",
    ],
    "Install": [
        "Quickstart",
        "Server requirements",
        "Installation",
        "Docker Compose",
        "First login",
        "Manual steps after installation",
    ],
    "Agents": ["Adding agents", "Importing from another RMM", "Agent builds"],
    "Operate": [
        "Updating",
        "Firewall",
        "Backups",
        "Restore",
        "RustDesk server",
        "SSO and reporting limits",
        "External MeshCentral",
        "Troubleshooting",
    ],
    "Project": [
        "Development and gates",
        "Secrets",
        "Outbound connections",
        "Third-party software",
        "Roadmap",
        "Contributing",
        "Sponsoring",
        "Use at your own risk",
        "Lawful use and data protection",
        "Trademarks",
        "License",
    ],
}
# the "](target)" end of any link, nested badge links included
LINK = re.compile(r"(\])\(([^)\s]+)\)")
# a screenshot on its own line
SHOT = re.compile(r"^!\[([^\]]*)\]\((\S+)\)$")
# "| **216** | scripts in the script library |" under an empty header row
STAT = re.compile(r"^\|\s*\*\*([^*|]+)\*\*\s*\|\s*([^|]+?)\s*\|$")
# home page tiles for the "What it does" bullets: (start of the bullet, title,
# icon in docs/pages/assets/css/ulrmm.css); a bullet not listed gets no title
FEATURES = (
    ("Clients, sites", "Dashboard and access", "users"),
    ("Remote desktop", "Remote access", "remote"),
    ("Scripts", "Scripts, tasks and checks", "code"),
    ("Patch management", "Patch management", "patch"),
    ("Software and hardware inventory", "Inventory", "list"),
    ("Sleep and Wake-on-LAN", "Power and maintenance", "power"),
    ("Endpoint health", "Health and network monitoring", "pulse"),
    ("Software packages", "Software packages", "package"),
    ("Reporting", "Reporting and branding", "chart"),
)


def slug(heading: str) -> str:
    # GitHub's anchor rule: lower case, drop punctuation, spaces to dashes
    text = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return text.replace(" ", "-")


def sections(markdown: str):
    """(title, body) per "## " heading outside code fences; the part before
    the first one comes back with the title None."""
    title, lines, fence = None, [], False
    for line in markdown.splitlines():
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("## "):
            yield title, "\n".join(lines).strip("\n")
            title, lines = line[3:].strip(), []
        else:
            lines.append(line)
    yield title, "\n".join(lines).strip("\n")


def anchors(body: str):
    fence = False
    for line in body.splitlines():
        if line.startswith("```"):
            fence = not fence
        elif not fence and re.match(r"#{3,6} ", line):
            yield slug(line.lstrip("#"))


def rewrite(body: str, here: str, pages: dict, base: str) -> str:
    """here: the source file's directory relative to the repository root."""

    def link(m):
        label, target = m.group(1), m.group(2)
        if re.match(r"^[a-z]+:", target):
            return m.group(0)
        path, _, frag = target.partition("#")
        if not path:
            page = pages.get(frag)
            if page is None:
                return m.group(0)
            return f"{label}({base}/{page[0]}/{'#' + frag if page[1] else ''})"
        full = (Path(here) / path).as_posix().removeprefix("./")
        while "/../" in full or full.startswith("../"):
            full = re.sub(r"[^/]+/\.\./", "", full, count=1).removeprefix("../")
        if full.startswith("docs/showcase/"):
            return f"{label}({base}/showcase/{full.rsplit('/', 1)[1]})"
        if full == "docs/SHOWCASE.md":
            return f"{label}({base}/tour/)"
        if full == "docs/VERSIONING_AND_RELEASES.md":
            return f"{label}({base}/versioning/)"
        if full.startswith("docs/") and full.endswith(".pdf"):
            return f"{label}({base}/{full.removeprefix('docs/')})"
        return f"{label}({REPO}{full}{'#' + frag if frag else ''})"

    out, fence = [], False
    for line in body.splitlines():
        if line.startswith("```"):
            fence = not fence
        out.append(line if fence else LINK.sub(link, line))
    return "\n".join(out)


def inline(text: str) -> str:
    """Markdown text as HTML for the generated blocks: escaped, `code` kept."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))


def figure(src: str, alt: str, caption: str, href: str = "") -> str:
    """A screenshot card linking to the full image, or with href to the tour."""
    src = html.escape(src)
    link = (
        f'href="{html.escape(href)}" title="Showcase tour"' if href else f'href="{src}"'
    )
    return (
        f'<figure class="shot"><a {link}><img src="{src}" '
        f'alt="{html.escape(alt)}" loading="lazy"></a>\n'
        f"<figcaption>{inline(caption)}</figcaption></figure>"
    )


def figures(body: str) -> str:
    """Screenshots in a row, each with an optional *caption* line under it,
    become one card grid; a card links to the full image."""
    out, run, fence = [], [], False
    lines = body.splitlines()

    def flush():
        if run:
            out.extend(["", '<div class="shot-grid">', *run, "</div>", ""])
            run.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            fence = not fence
        m = None if fence else SHOT.match(line)
        if m:
            alt, src = m.groups()
            caption = alt
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if re.fullmatch(r"\*[^*]+\*", nxt):
                caption, i = nxt[1:-1], i + 1
            run.append(figure(src, alt, caption))
        elif line.strip() or not run:
            flush()
            out.append(line)
        i += 1
    flush()
    return "\n".join(out)


def stats(body: str) -> str:
    """A two-column table of bold figures with an empty header becomes stat tiles."""
    lines, out, i, fence = body.splitlines(), [], 0, False
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            fence = not fence
        if not fence and re.fullmatch(r"\|\s*\|\s*\|", line) and i + 1 < len(lines):
            j, tiles = i + 2, []
            while j < len(lines) and (m := STAT.match(lines[j])):
                tiles.append(
                    f'<div class="stat"><span class="stat-value">{inline(m.group(1))}</span>\n'
                    f'<span class="stat-label">{inline(m.group(2))}</span></div>'
                )
                j += 1
            if tiles and re.fullmatch(r"\|[-: ]+\|[-: ]+\|", lines[i + 1]):
                out.append("\n".join(['<div class="stats">', *tiles, "</div>"]))
                i = j
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


def landing(intro: str, what: str, showcase: str, pages: dict, base: str) -> str:
    """The home page: hero, the rest of the intro, feature tiles, screenshots."""
    # badges load images from other hosts, and "This file ..." means the README
    paras = [
        p
        for p in intro.split("\n\n")
        if p.strip() and not p.startswith(("[![", "This file"))
    ]
    lead, _, rest = " ".join(paras[0].split()).partition(". ")
    lead = lead.rstrip(".") + "."
    m = re.search(r" for (.+?) endpoints", lead)
    chips = re.split(r", | and ", m.group(1)) if m else []
    shots = f"{base}/showcase"
    hero = [
        '<section class="hero">',
        '<div class="hero-text">',
        f'<img class="hero-logo" src="{base}/assets/images/ulrmm-logo.png" alt="" width="64" height="64">',
        '<h1 class="hero-title">UniversalLocal RMM</h1>',
        f'<p class="hero-lead">{inline(lead)}</p>',
        '<div class="hero-actions">',
        f'<a class="btn btn-primary" href="{base}/quickstart/">Quickstart</a>',
        f'<a class="btn" href="{base}/tour/">Showcase tour</a>',
        '<a class="btn" href="https://github.com/RiDDiX/ulrmm">GitHub</a>',
        "</div>",
    ]
    if chips:
        hero += [
            '<ul class="chips" aria-label="Endpoint platforms">',
            *(f"<li>{inline(c)}</li>" for c in chips),
            "</ul>",
        ]
    hero += [
        "</div>",
        f'<a class="hero-shot" href="{base}/tour/" aria-label="Showcase tour">',
        '<span class="shot-bar" aria-hidden="true"><span></span><span></span><span></span></span>',
        f'<img class="only-light" src="{shots}/devices.png" alt="Devices workspace" width="1600" height="1000">',
        f'<img class="only-dark" src="{shots}/devices-dark.png" alt="Devices workspace, dark mode" width="1600" height="1000">',
        "</a>",
        "</section>",
    ]

    tiles = []
    for item in re.findall(r"^- (.+(?:\n  .+)*)", what, re.M):
        text = " ".join(item.split())
        title, icon = next(
            ((t, i) for p, t, i in FEATURES if text.startswith(p)), ("", "dot")
        )
        if title and text.startswith(title + ":"):
            text = text[len(title) + 1 :].strip()
            text = text[:1].upper() + text[1:]
        # no heading: it would get an anchor and a search entry of its own
        head = f'<p class="tile-title">{html.escape(title)}</p>\n' if title else ""
        tiles.append(
            f'<div class="tile"><span class="tile-icon ico-{icon}" aria-hidden="true"></span>\n'
            f"{head}<p>{inline(text)}</p></div>"
        )

    # the screenshots before the first sub heading, as cards linking to the tour
    top = showcase.split("\n### ")[0]
    strip = [
        figure(m.group(2), m.group(1), m.group(1), f"{base}/tour/")
        for m in map(SHOT.match, rewrite(top, "", pages, base).splitlines())
        if m
    ]
    text = [p for p in top.split("\n\n") if p.strip() and not SHOT.match(p.strip())]

    parts = ["\n".join(hero)]
    if rest or paras[1:]:
        parts.append(
            rewrite("\n\n".join(([rest] if rest else []) + paras[1:]), "", pages, base)
        )
    parts += ["## What it does", "\n".join(['<div class="tiles">', *tiles, "</div>"])]
    parts += ["## Showcase", "\n".join(['<div class="shot-grid">', *strip, "</div>"])]
    parts += [rewrite(p, "", pages, base) for p in text]
    return "\n\n".join(parts)


def page(path: Path, front: dict, body: str) -> None:
    head = "".join(f"{k}: {v}\n" for k, v in front.items())
    # raw: nothing in the docs is meant as a Liquid tag
    path.write_text(f"---\n{head}---\n\n{{% raw %}}\n{body}\n{{% endraw %}}\n")


def quote(text: str) -> str:
    return '"' + text.replace('"', '\\"') + '"'


def build(out: Path, base: str) -> list[str]:
    readme = (ROOT / "README.md").read_text()
    parts = list(sections(readme))
    intro, rest = parts[0][1], parts[1:]

    group_of = {t: g for g, titles in GROUPS.items() for t in titles}
    # anchor -> (page slug, is a sub heading)
    pages = {}
    for title, body in rest:
        pages[slug(title)] = (slug(title), False)
        for a in anchors(body):
            pages.setdefault(a, (slug(title), True))

    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "docs/pages", out)
    config = (ROOT / "docs/pages/_config.yml").read_text()
    version = (ROOT / "VERSION").read_text().strip()
    # stated, not guessed: Pages metadata can give a wrong one before the first deploy
    (out / "_config.yml").write_text(
        f'{config}baseurl: "{base}"\nulrmm_version: "{version}"\n'
    )
    shutil.copytree(ROOT / "docs/showcase", out / "showcase")
    for pdf in (ROOT / "docs").glob("*.pdf"):
        shutil.copy(pdf, out / pdf.name)

    # the intro starts with the "# " title line, the home page has its own
    intro = re.sub(r"\A# .*\n+", "", intro)
    section = dict(rest)
    page(
        out / "index.md",
        # its text is on the What it does and Showcase pages too
        {"title": "Home", "nav_order": 1, "permalink": "/", "search_exclude": "true"},
        landing(intro, section["What it does"], section["Showcase"], pages, base),
    )

    groups = list(GROUPS) + ["More"]
    used = {t for t, _ in rest}
    for n, group in enumerate(groups, start=2):
        titles = GROUPS.get(group) or [t for t, _ in rest if t not in group_of]
        if not any(t in used for t in titles):
            continue
        page(
            out / f"{slug(group)}.md",
            {
                "title": group,
                "nav_order": n,
                "has_children": "true",
                "permalink": f"/{slug(group)}/",
            },
            f"# {group}",
        )
    order = {t: i for titles in GROUPS.values() for i, t in enumerate(titles)}
    missing = []
    for i, (title, body) in enumerate(rest):
        group = group_of.get(title, "More")
        if group == "More":
            missing.append(title)
        page(
            out / f"{slug(title)}.md",
            {
                "title": quote(title),
                "parent": group,
                "nav_order": order.get(title, 100 + i),
                "permalink": f"/{slug(title)}/",
            },
            f"# {title}\n\n" + figures(stats(rewrite(body, "", pages, base))),
        )

    extra = (
        ("docs/SHOWCASE.md", "Showcase tour", "tour", "Overview", 50),
        (
            "docs/VERSIONING_AND_RELEASES.md",
            "Versioning and releases",
            "versioning",
            "Project",
            50,
        ),
    )
    for src, title, name, group, n in extra:
        body = re.sub(r"\A# .*\n+", "", (ROOT / src).read_text())
        page(
            out / f"{name}.md",
            {
                "title": quote(title),
                "parent": group,
                "nav_order": n,
                "permalink": f"/{name}/",
            },
            f"# {title}\n\n" + figures(stats(rewrite(body, "docs", pages, base))),
        )
    return missing


def main(argv) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    base = ""
    if "--baseurl" in argv:
        base = argv[argv.index("--baseurl") + 1].rstrip("/")
    missing = build(Path(argv[0]), base)
    if missing:
        print("sections without a group (shown under More):", ", ".join(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
