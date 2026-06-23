from dataclasses import dataclass, asdict

BODY_LIMIT = 8192
_HEADER_KEYS = {"content-type", "content-length", "location", "server",
                "x-powered-by", "www-authenticate"}


@dataclass
class Artifact:
    tool: str
    wstg: str
    method: str
    url: str
    role: str
    status: int
    headers_subset: dict
    body: str
    baseline_status: int | None = None


def build_artifact(*, tool, wstg, method, url, role, status, headers, body,
                   baseline_status=None) -> dict:
    hs = {k: v for k, v in (headers or {}).items() if k.lower() in _HEADER_KEYS}
    art = Artifact(tool=tool, wstg=wstg, method=method, url=url,
                   role=role or "anonymous", status=int(status), headers_subset=hs,
                   body=(body or "")[:BODY_LIMIT], baseline_status=baseline_status)
    return asdict(art)


def artifact_from_dict(d: dict) -> Artifact:
    return Artifact(**{k: d.get(k) for k in Artifact.__dataclass_fields__})
