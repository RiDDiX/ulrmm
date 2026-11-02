# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Builds the documentation site source from README.md and docs/.

    python3 riddix/scripts/docs_site.py <out dir> [--baseurl /ulrmm]

README.md stays the only source: every "## " section becomes a page,
grouped in the navigation by GROUPS, plus the showcase (docs/SHOWCASE.md)
and the versioning notes. Links between sections point to the pages, links
to other repository files to GitHub. The pages workflow builds the result
with Jekyll and the just-the-docs theme (docs/pages/_config.yml)."""

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
    out.mkdir(parents=True)
    config = (ROOT / "docs/pages/_config.yml").read_text()
    # stated, not guessed: Pages metadata can give a wrong one before the first deploy
    (out / "_config.yml").write_text(f'{config}baseurl: "{base}"\n')
    shutil.copytree(ROOT / "docs/showcase", out / "showcase")
    for pdf in (ROOT / "docs").glob("*.pdf"):
        shutil.copy(pdf, out / pdf.name)

    # the intro starts with the "# " title line, the home page has its own
    intro = re.sub(r"\A# .*\n+", "", intro)
    page(
        out / "index.md",
        {"title": "Home", "nav_order": 1, "permalink": "/"},
        "# UniversalLocal RMM\n\n" + rewrite(intro, "", pages, base),
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
            f"# {title}\n\n" + rewrite(body, "", pages, base),
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
            f"# {title}\n\n" + rewrite(body, "docs", pages, base),
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
