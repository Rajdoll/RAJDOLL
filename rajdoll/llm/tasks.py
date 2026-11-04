"""The five LLM tasks (TRD 5.2): output schemas, prompts, and what each call may affect.

Every output is a pydantic model with tight bounds: tags come from the fixed tag list, values and
requests have length limits, and the mini-loop's requests are checked again before anything is
sent. Prompts are Jinja2 templates (`rajdoll/llm/prompts/`); target content reaches them only as
`data_block`s, and every system prompt carries `DATA_RULE`. Each caller keeps a rule-based
fallback for an outcome that is not `ok` (TRD P2).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, Field, field_validator

from rajdoll.core.enums import LlmTaskKind
from rajdoll.llm.context import DATA_RULE
from rajdoll.llm.gateway import LlmTask
from rajdoll.services.tagging import TAG_LABELS

PROMPTS = Path(__file__).parent / "prompts"
_FORBIDDEN = {chr(c) for c in range(0x20) if c not in (0x09,)} | {"\x7f"}

Tag = Literal[tuple(TAG_LABELS)]  # type: ignore[valid-type]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# -- classify_endpoint (PRD F-17) ----------------------------------------------------------


class EndpointTags(_Strict):
    index: int = Field(ge=0, le=50)
    tags: list[Tag] = Field(max_length=8)  # type: ignore[valid-type]
    reason: str = Field(default="", max_length=200)


class Classification(_Strict):
    endpoints: list[EndpointTags] = Field(max_length=20)


# -- build_input (PRD F-18) ----------------------------------------------------------------


class ParameterValue(_Strict):
    name: str = Field(min_length=1, max_length=100)
    value: str = Field(max_length=200)

    @field_validator("value")
    @classmethod
    def _printable(cls, value: str) -> str:
        if set(value) & _FORBIDDEN:
            raise ValueError("value must not contain control characters")
        return value


class InputValues(_Strict):
    values: list[ParameterValue] = Field(max_length=30)


# -- judge_response (PRD F-19) -------------------------------------------------------------


class Judgement(_Strict):
    answer: Literal["ya", "tidak", "ragu"]
    reason: str = Field(max_length=500)
    relevant_part: str = Field(default="", max_length=300)


# -- verification_step (PRD F-20, TRD 6.4) -------------------------------------------------


class ProposedRequest(_Strict):
    method: Literal["GET", "POST", "PUT", "PATCH"]
    path: str = Field(min_length=1, max_length=500)
    query: dict[str, str] = Field(default_factory=dict, max_length=20)
    body: dict[str, str] | None = Field(default=None, max_length=20)
    expect: str = Field(default="", max_length=300)

    @field_validator("path")
    @classmethod
    def _relative(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "://" in value:
            raise ValueError("path must be relative to the target host (start with one '/')")
        if set(value) & _FORBIDDEN or " " in value:
            raise ValueError("path must not contain spaces or control characters")
        return value


class VerificationStep(_Strict):
    requests: list[ProposedRequest] = Field(min_length=1, max_length=3)
    # A better normal value for the tested parameter, for the validator's next run.
    base_value: str | None = Field(default=None, max_length=200)
    reasoning: str = Field(default="", max_length=500)

    @field_validator("base_value")
    @classmethod
    def _printable(cls, value: str | None) -> str | None:
        if value is not None and set(value) & _FORBIDDEN:
            raise ValueError("base_value must not contain control characters")
        return value


# -- triage_finding (PRD F-21) -------------------------------------------------------------


class Triage(_Strict):
    explanation: str = Field(max_length=1500)
    impact: str = Field(default="", max_length=800)
    fix: str = Field(default="", max_length=800)
    manual_test_suggestions: list[str] = Field(default_factory=list, max_length=5)
    possible_duplicates: list[int] = Field(default_factory=list, max_length=10)

    @field_validator("manual_test_suggestions")
    @classmethod
    def _short(cls, value: list[str]) -> list[str]:
        return [item[:300] for item in value]


CLASSIFY = LlmTask(LlmTaskKind.CLASSIFY_ENDPOINT, Classification, max_tokens=600)
BUILD_INPUT = LlmTask(LlmTaskKind.BUILD_INPUT, InputValues, max_tokens=400)
JUDGE = LlmTask(LlmTaskKind.JUDGE_RESPONSE, Judgement, max_tokens=300)
VERIFY = LlmTask(LlmTaskKind.VERIFICATION_STEP, VerificationStep, max_tokens=700)
TRIAGE = LlmTask(LlmTaskKind.TRIAGE_FINDING, Triage, max_tokens=800)

_env = Environment(
    loader=FileSystemLoader(PROMPTS),
    autoescape=False,  # noqa: S701 (plain-text prompts; target content arrives as data blocks)
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


def messages(name: str, **context: Any) -> list[dict[str, str]]:
    """System and user messages from `prompts/<name>.system.j2` and `<name>.user.j2`."""
    values = {"data_rule": DATA_RULE, "tag_labels": TAG_LABELS, **context}
    return [
        {"role": "system", "content": _env.get_template(f"{name}.system.j2").render(values)},
        {"role": "user", "content": _env.get_template(f"{name}.user.j2").render(values).strip()},
    ]


def judge_response(
    llm: Any,
    question: str,
    request: str,
    response_a: str,
    response_b: str | None = None,
    *,
    finding_id: int | None = None,
    keywords: tuple[str, ...] = (),
) -> Judgement:
    """`judge_response` (PRD F-19) through `ctx.llm`; "ragu" (manual check) without an LLM.

    The answer only steers what a module reports as a candidate; a validator still decides.
    """
    from rajdoll.llm.context import data_block, trim_response

    outcome = llm(
        JUDGE,
        messages(
            "judge_response",
            question=question,
            request=data_block("request", request[:1500]),
            response_a=data_block("respons akun A", trim_response(response_a, keywords, 1500)),
            response_b=(
                data_block("respons akun B", trim_response(response_b, keywords, 1500))
                if response_b
                else None
            ),
        ),
        finding_id=finding_id,
    )
    if outcome is None or not outcome.ok:
        return Judgement(answer="ragu", reason="LLM tidak tersedia; perlu cek manual.")
    return outcome.value
