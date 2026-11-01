from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from sbom_diff import render
from sbom_diff.diff import diff
from sbom_diff.parsers import SbomParseError, load

_RENDERERS = {
    "text": render.to_text,
    "markdown": render.to_markdown,
    "json": render.to_json,
}


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sbom-diff",
        description="Compare two SBOMs. Exit: 0 identical, 1 differences, 2 error.",
    )
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("-f", "--format", choices=_RENDERERS, default="text")
    args = p.parse_args(argv)
    try:
        result = diff(load(args.old), load(args.new))
    except (SbomParseError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(_RENDERERS[args.format](result))
    return 1 if result else 0


if __name__ == "__main__":
    sys.exit(main())
