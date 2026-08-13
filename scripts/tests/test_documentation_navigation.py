from __future__ import annotations

from pathlib import Path
import re
import unittest
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
DOCS = ROOT / "docs"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


class DocumentationNavigationTests(unittest.TestCase):
    def test_root_readme_stays_compact_and_routes_to_task_guides(self) -> None:
        raw = README.read_bytes()
        text = raw.decode("utf-8")

        self.assertLessEqual(len(raw), 32 * 1024)
        self.assertLessEqual(len(text.splitlines()), 400)

        for heading in (
            "## Why pcbex",
            "## Quick start",
            "## Usage",
            "## Configuration",
            "## Architecture",
            "## Integrations",
            "## Documentation",
            "## Development",
            "## Security",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

        for guide in (
            "GETTING_STARTED.md",
            "WORKFLOWS.md",
            "ARCHITECTURE.md",
            "INTEGRATIONS.md",
            "TRUST_MODEL.md",
            "README.md",
        ):
            with self.subTest(guide=guide):
                self.assertIn(f"docs/{guide}", text)

    def test_documentation_index_covers_every_markdown_guide(self) -> None:
        index = (DOCS / "README.md").read_text(encoding="utf-8")
        focused = sorted(path for path in DOCS.glob("*.md") if path.name != "README.md")

        self.assertGreater(len(focused), 0)
        for path in focused:
            with self.subTest(path=path.name):
                self.assertIn(f"({path.name})", index)

    def test_every_relative_markdown_link_target_exists(self) -> None:
        sources = [README, *sorted(DOCS.glob("*.md"))]

        for source in sources:
            text = source.read_text(encoding="utf-8")
            for raw_target in MARKDOWN_LINK.findall(text):
                target = raw_target.strip().split()[0].strip("<>")
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                path_text = unquote(target.split("#", 1)[0])
                if not path_text:
                    continue
                resolved = (source.parent / path_text).resolve()
                with self.subTest(source=source.relative_to(ROOT), target=target):
                    self.assertTrue(resolved.is_relative_to(ROOT))
                    self.assertTrue(resolved.exists())


if __name__ == "__main__":
    unittest.main()
