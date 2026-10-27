"""Severity levels and the strict output schema the detective must match.

PLAN:
1. Severity is ordered: low < medium < high < critical.
2. DetectiveOutput is strict: every field required, no extra keys, no type coercion.
3. Length caps stop a reply from carrying a large payload.
"""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

ORDER = ("low", "medium", "high", "critical")


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def rank(severity: Severity) -> int:
    return ORDER.index(severity.value)


class DetectiveOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    severity: Severity
    summary: str = Field(max_length=500)
    findings: list[Annotated[str, Field(max_length=200)]] = Field(max_length=10)
