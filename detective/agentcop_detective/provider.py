"""Providers answer a prompt with text. They get no tools, no files, and no network from us.

PLAN:
1. A provider is anything with `complete(prompt) -> str`.
2. TemplateProvider is the offline default. It reads the baseline from the prompt and repeats it.
   It never raises severity, because it does no analysis.
"""

import re

_BASELINE = re.compile(r"Baseline: (low|medium|high|critical)\b")


class TemplateProvider:
    def complete(self, prompt: str) -> str:
        match = _BASELINE.search(prompt)
        if match is None:
            return ""  # no baseline found: the reply is invalid, so the detective keeps its baseline
        return (
            '{"severity": "' + match.group(1) + '", '
            '"summary": "Offline template review. No model used; severity kept at baseline.", '
            '"findings": []}'
        )
