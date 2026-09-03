import re
from pathlib import Path

import frlgtrade
import frlgtrade_host


def _options(parser):
    return {
        option
        for action in parser._actions
        for option in action.option_strings
    }


def test_readme_options_exist_in_an_entry_point():
    readme = Path("README.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"`(--[a-z][a-z0-9-]*)", readme))
    available = _options(frlgtrade.build_parser()) | _options(frlgtrade_host.build_parser())
    assert documented <= available, sorted(documented - available)


def test_readme_local_links_exist():
    readme = Path("README.md").read_text(encoding="utf-8")
    links = re.findall(r"\[[^]]+\]\((?!https?://)([^)#]+)", readme)
    assert links
    assert all(Path(link).exists() for link in links)
