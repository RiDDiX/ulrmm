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
