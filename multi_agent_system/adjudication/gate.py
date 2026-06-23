from .artifact import Artifact

_LEAK_MARKERS = ("stack trace", "traceback", "exception", "sql syntax", "ora-",
                 "<b>warning</b>", "/home/", "/var/www", "syntaxerror",
                 "nullpointerexception", "undefined index")


def should_adjudicate(art: Artifact) -> bool:
    wstg = (art.wstg or "").upper()
    body = art.body or ""
    if wstg.startswith("WSTG-ATHZ"):
        return 200 <= art.status < 300 and len(body) > 0
    if wstg.startswith("WSTG-BUSL"):
        return 200 <= art.status < 300 and len(body) > 0
    if wstg.startswith(("WSTG-ERRH", "WSTG-INFO")):
        return art.status >= 500 or any(m in body.lower() for m in _LEAK_MARKERS)
    return False
