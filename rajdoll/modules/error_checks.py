"""Error Handling checks (WSTG-ERRH-01, -02).

A parameter gets values that commonly break parsing (quotes, a non-number, a huge number,
brackets, a NUL byte, a long value). A response that shows a stack trace, a framework debug
page, or a server-side file path, where the normal value's response does not, leaks internal
details. Patterns are specific to known runtimes so ordinary pages ("error" in a sentence) do
not count. SQL error messages are left to Input Validation (they are SQL injection evidence).

Once per host, a random path that cannot exist shows whether the not-found page is a debug page.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

PAYLOADS: tuple[tuple[str, str], ...] = (
    ("kutip", "'\"\\"),
    ("bukan angka", "abc"),
    ("angka sangat besar", "-99999999999999999999"),
    ("kurung", "{}[("),
    ("byte NUL", "rajdoll\x00"),
    ("nilai sangat panjang", "A" * 2048),
)

ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "stack trace Python",
        re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+, in "),
    ),
    (
        "stack trace Java",
        re.compile(
            r"\bat [a-z][\w$]*(?:\.[\w$]+)+\([\w$]+\.java:\d+\)"
            r"|java\.lang\.\w+(?:Exception|Error)\b"
        ),
    ),
    ("halaman error Spring", re.compile(r"Whitelabel Error Page")),
    (
        "error PHP",
        re.compile(
            r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:.{0,300}? "
            r"in (?:<b>)?[\w/\\.:-]+\.php(?:</b>)? on line (?:<b>)?\d+",
            re.S,
        ),
    ),
    ("stack trace PHP", re.compile(r"Stack trace:\s*(?:<br\s*/?>)?\s*#0 ")),
    (
        "halaman error ASP.NET",
        re.compile(
            r"Server Error in '[^']*' Application"
            r"|ASP\.NET is configured to show verbose error messages"
        ),
    ),
    ("stack trace .NET", re.compile(r"\bat System\.[\w.]+\(|\[\w+Exception: ")),
    (
        "stack trace Node.js",
        re.compile(r"\n\s+at [\w.<>$\[\] ]+ \((?:/|[A-Za-z]:\\)[^)\n]+:\d+:\d+\)"),
    ),
    ("stack trace Ruby", re.compile(r"\.rb:\d+:in `|ActionController::\w+Error")),
    (
        "halaman debug Django",
        re.compile(
            r"You(?:'|&#x27;|&#39;)re seeing this error because you have <code>DEBUG = True</code>"
            r"|Using the URLconf defined in"
        ),
    ),
    (
        "halaman debug Laravel",
        re.compile(
            r"Whoops, looks like something went wrong|Illuminate\\[A-Z]\w+|vendor/laravel/framework"
        ),
    ),
    ("debugger Werkzeug", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    ("panic Go", re.compile(r"goroutine \d+ \[running\]")),
    (
        "path file server",
        re.compile(
            # Not in an HTML attribute (`src="/opt/x.js"` is a URL, not a server path).
            r"(?<!=[\"'])(?:/(?:var/www|home/[\w.-]+|usr/(?:local/)?lib|opt)/[\w./-]+"
            r"\.(?:php|py|rb|java|js|go|cs)\b|[A-Z]:\\(?:inetpub|Users|wamp|xampp)\\[\w\\.-]+)"
        ),
    ),
)


def leaks(text: str) -> list[str]:
    """The names of the error patterns `text` shows."""
    return [name for name, pattern in ERROR_PATTERNS if pattern.search(text)]


def new_leaks(error_text: str, normal_text: str) -> list[str]:
    """Patterns in the error response that the normal response does not show."""
    normal = set(leaks(normal_text))
    return [name for name in leaks(error_text) if name not in normal]


def random_path() -> str:
    return f"/rajdoll-{secrets.token_hex(6)}"


@dataclass(frozen=True)
class Leak:
    payload_name: str
    payload: str
    patterns: tuple[str, ...]

    @property
    def note(self) -> str:
        return f"Nilai uji ({self.payload_name}) memunculkan {', '.join(self.patterns)}."
