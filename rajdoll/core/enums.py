"""Allowed values for status and kind columns (BSD sections 3-6).

Stored as `text` with CHECK constraints generated from these enums, so adding a value
means changing the enum here and adding an Alembic migration.
"""

from enum import StrEnum


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    ACTIVE = "active"
    DONE = "done"


class AuthMethod(StrEnum):
    PASTED = "pasted"
    AUTO_LOGIN = "auto_login"


class SessionStatus(StrEnum):
    UNKNOWN = "unknown"
    VALID = "valid"
    INVALID = "invalid"


class EndpointSource(StrEnum):
    CRAWL = "crawl"
    FUZZ = "fuzz"
    JS = "js"
    MANUAL = "manual"
    BURP_PASTE = "burp_paste"


class TagSource(StrEnum):
    RULE = "rule"
    LLM = "llm"
    USER = "user"


class ScanKind(StrEnum):
    SCAN = "scan"
    RETEST = "retest"


class ScanProfile(StrEnum):
    FULL = "full"
    CUSTOM = "custom"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_CHECKPOINT = "awaiting_checkpoint"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanStage(StrEnum):
    RECON = "recon"
    PLANNING = "planning"
    TESTING = "testing"
    VALIDATION = "validation"
    AI_TRIAGE = "ai_triage"
    RETEST = "retest"


class PausedReason(StrEnum):
    MANUAL = "manual"
    SESSION_EXPIRED = "session_expired"
    WAF_BLOCKED = "waf_blocked"


class CheckpointResolution(StrEnum):
    USER_CONTINUED = "user_continued"
    AUTO_CONTINUED = "auto_continued"
    DISABLED = "disabled"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class EventLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class EventType(StrEnum):
    STAGE_CHANGED = "stage_changed"
    TASK_FINISHED = "task_finished"
    FINDING_CREATED = "finding_created"
    CHECKPOINT_WAITING = "checkpoint_waiting"
    PAUSED = "paused"
    RESUMED = "resumed"
    SESSION_EXPIRED = "session_expired"
    BLOCK_SUSPECTED = "block_suspected"
    BLOCK_SUSTAINED = "block_sustained"
    RATE_REDUCED = "rate_reduced"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NOTICE = "notice"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Validation(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_MANUAL_CHECK = "needs_manual_check"
    MANUAL = "manual"


class Decision(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RetestResult(StrEnum):
    NOT_TESTED = "not_tested"
    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    UNTESTABLE = "untestable"
    NEEDS_MANUAL_RETEST = "needs_manual_retest"


class RetestOutcome(StrEnum):
    """Result of one finding in one retest round (no `not_tested`)."""

    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    UNTESTABLE = "untestable"
    NEEDS_MANUAL_RETEST = "needs_manual_retest"


class EvidenceKind(StrEnum):
    DETECTION = "detection"
    VALIDATION = "validation"
    VERIFICATION_ROUND = "verification_round"
    RESEND = "resend"
    RETEST = "retest"
    MANUAL = "manual"


class LlmTaskKind(StrEnum):
    CLASSIFY_ENDPOINT = "classify_endpoint"
    BUILD_INPUT = "build_input"
    JUDGE_RESPONSE = "judge_response"
    VERIFICATION_STEP = "verification_step"
    TRIAGE_FINDING = "triage_finding"


class LlmCallStatus(StrEnum):
    OK = "ok"
    SCHEMA_RETRY_OK = "schema_retry_ok"
    SCHEMA_ERROR = "schema_error"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED_BUDGET = "skipped_budget"


class RequestKind(StrEnum):
    HTTP = "http"
    TOOL_EXEC = "tool_exec"


class RequestOutcome(StrEnum):
    FORWARDED = "forwarded"
    BLOCKED_SCOPE = "blocked_scope"
    BLOCK_SUSPECTED = "block_suspected"
    ERROR = "error"


class ReportKind(StrEnum):
    VA = "va"
    RETEST = "retest"
