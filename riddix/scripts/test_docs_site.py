#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""python3 -m unittest riddix/scripts/test_docs_site.py (or run this file)."""

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docs_site  # noqa: E402


class TestDocsSite(unittest.TestCase):
    def test_rewrite(self):
        pages = {"backups": ("backups", False), "options": ("installation", True)}
        body = (
            "[a](#backups) [b](#options) [c](LICENSE.md) "
            "[![x](https://img/x.svg)](SECURITY.md) ![s](docs/showcase/a.png) "
            "[t](docs/SHOWCASE.md) [u](https://example.com) [v](#nowhere)\n"
            "```\n[d](LICENSE.md)\n```"
        )
        out = docs_site.rewrite(body, "", pages, "/ulrmm")
        blob = docs_site.REPO
        self.assertIn("[a](/ulrmm/backups/)", out)
        self.assertIn("[b](/ulrmm/installation/#options)", out)
        self.assertIn(f"[c]({blob}LICENSE.md)", out)
        self.assertIn(f"[![x](https://img/x.svg)]({blob}SECURITY.md)", out)
        self.assertIn("![s](/ulrmm/showcase/a.png)", out)
        self.assertIn("[t](/ulrmm/tour/)", out)
        self.assertIn("[u](https://example.com)", out)
        self.assertIn("[v](#nowhere)", out)
        self.assertIn("```\n[d](LICENSE.md)\n```", out, "code stays as written")
        self.assertIn(
            "![p](/ulrmm/showcase/p.png)",
            docs_site.rewrite("![p](showcase/p.png)", "docs", pages, "/ulrmm"),
        )

    def test_figures(self):
        body = (
            "Text\n\n![A <b>](/b/showcase/a.png)\n*First*\n\n"
            "![B](/b/showcase/b.png)\n\nAfter\n```\n![C](c.png)\n```"
        )
        out = docs_site.figures(body)
        self.assertEqual(out.count('<div class="shot-grid">'), 1, "one grid per run")
        self.assertIn(
            '<a href="/b/showcase/a.png"><img src="/b/showcase/a.png" alt="A &lt;b&gt;"',
            out,
        )
        self.assertIn("<figcaption>First</figcaption>", out)
        self.assertIn(
            "<figcaption>B</figcaption>", out, "the alt text without a caption"
        )
        self.assertNotIn("*First*", out)
        self.assertIn("</div>\n\nAfter", out)
        self.assertIn("```\n![C](c.png)\n```", out, "code stays as written")

    def test_stats(self):
        body = "| | |\n|---:|:---|\n| **216** | scripts |\n| **9** | check `types` |\n\nText"
        out = docs_site.stats(body)
        self.assertIn(
            '<span class="stat-value">216</span>\n<span class="stat-label">scripts</span>',
            out,
        )
        self.assertIn("check <code>types</code>", out)
        self.assertNotIn("|", out)
        self.assertTrue(out.endswith("\n\nText"))
        table = "| A | B |\n|---|---|\n| **1** | x |"
        self.assertEqual(docs_site.stats(table), table, "a table with a header stays")

    def test_home_page(self):
        readme = (docs_site.ROOT / "README.md").read_text()
        what = dict(list(docs_site.sections(readme))[1:])["What it does"]
        for base in ("", "/ulrmm"):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "site"
                docs_site.build(out, base)
                index = (out / "index.md").read_text()
                self.assertIn('<section class="hero">', index)
                self.assertIn(f'href="{base}/quickstart/"', index)
                self.assertIn("<li>Windows</li>", index)
                self.assertIn("<li>FreeBSD/TrueNAS</li>", index)
                bullets = len(re.findall(r"^- ", what, re.M))
                self.assertEqual(index.count('class="tile"'), bullets)
                self.assertNotIn('ico-dot"', index, "add new bullets to FEATURES")
                self.assertNotIn("<h3>", index, "tile titles are no headings")
                self.assertNotIn("<p align", index, "the README banner stays out")
                self.assertIn("| Single sign-on |", index)
                self.assertNotIn("[![", index, "no badge images from other hosts")
                # every local file the page points to is in the site
                for path in re.findall(r'(?:src|href)="([^"#]+)"', index):
                    if path.startswith("https://"):
                        continue
                    self.assertTrue(path.startswith(base + "/"), path)
                    local = path.removeprefix(base + "/")
                    if "." in local.rsplit("/", 1)[-1]:
                        self.assertTrue((out / local).exists(), path)
                    else:
                        self.assertTrue((out / f"{local.strip('/')}.md").exists(), path)
                config = (out / "_config.yml").read_text()
                version = (docs_site.ROOT / "VERSION").read_text().strip()
                self.assertIn(f'ulrmm_version: "{version}"', config)
                self.assertTrue((out / "assets/css/ulrmm.css").exists())
                tour = (out / "tour.md").read_text()
                self.assertIn('<div class="stats">', tour)
                # inline() renders only `code`, other Markdown would show as written
                for page in (index, tour):
                    for _, text in re.findall(
                        r'<(figcaption|p|span)(?: class="[^"]*")?>(.*?)</\1>', page
                    ):
                        self.assertNotRegex(text, r"\]\(|\*", text)

    def test_nav_icons_follow_groups(self):
        # ulrmm.css gives the sidebar icons by position: Home, then GROUPS
        css = (docs_site.ROOT / "docs/pages/assets/css/ulrmm.css").read_text()
        rules = re.findall(r"> \.nav-list-item:nth-child\((\d+)\)", css)
        self.assertEqual(rules, [str(n) for n in range(1, len(docs_site.GROUPS) + 2)])

    def test_every_readme_section_has_a_grouped_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "site"
            missing = docs_site.build(out, "")
            self.assertEqual(missing, [], "add new README sections to GROUPS")
            readme = (docs_site.ROOT / "README.md").read_text()
            for title, _ in list(docs_site.sections(readme))[1:]:
                self.assertTrue((out / f"{docs_site.slug(title)}.md").exists(), title)
            index = (out / "index.md").read_text()
            self.assertIn("{% raw %}", index)
            self.assertIn('baseurl: ""', (out / "_config.yml").read_text())
            # no relative repository link is left in a page
            for page in out.glob("*.md"):
                for target in re.findall(r"\]\(([^)\s]+)\)", page.read_text()):
                    self.assertTrue(
                        re.match(r"^(https?://|/|#|mailto:)", target),
                        f"{page.name}: {target}",
                    )


if __name__ == "__main__":
    unittest.main()
