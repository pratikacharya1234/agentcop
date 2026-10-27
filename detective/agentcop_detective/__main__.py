"""Run the detective on one bundle file: python -m agentcop_detective <bundle.json>"""

import json
import sys
from pathlib import Path

from .detective import investigate
from .provider import TemplateProvider


def main(argv):
    if len(argv) != 2:
        print("usage: python -m agentcop_detective <bundle.json>", file=sys.stderr)
        return 2
    bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    r = investigate(bundle, TemplateProvider())
    print(json.dumps({
        "severity": r.severity.value,
        "summary": r.summary,
        "findings": r.findings,
        "raised": r.raised,
        "discarded": r.discarded,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
