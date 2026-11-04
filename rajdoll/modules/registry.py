"""Which test modules exist (PRD 4, TRD 6.2).

`MODULE_LABELS` lists all twelve modules of the full profile with their Indonesian labels.
`available_modules()` returns the ones implemented so far; profiles may name the others, and
the engine reports them as not yet available instead of failing.
"""

import importlib
import os

from rajdoll.modules.base import Module

MODULE_LABELS: dict[str, str] = {
    "information_gathering": "Information Gathering",
    "configuration": "Configuration & Deployment",
    "identity": "Identity Management",
    "authentication": "Authentication",
    "authorization": "Authorization",
    "session": "Session Management",
    "input_validation": "Input Validation",
    "error_handling": "Error Handling",
    "cryptography": "Weak Cryptography",
    "business_logic": "Business Logic",
    "file_upload": "File Upload",
    "client_side": "Client-Side",
}


def available_modules() -> dict[str, Module]:
    from rajdoll.modules.information_gathering import InformationGathering

    modules: list[Module] = [InformationGathering()]
    found = {module.name: module for module in modules}
    # Tests (and later, plugins) can add modules: RAJDOLL_EXTRA_MODULES=package.module,...
    for path in filter(None, os.environ.get("RAJDOLL_EXTRA_MODULES", "").split(",")):
        extra = importlib.import_module(path.strip())
        for module in getattr(extra, "MODULES", []):
            found[module.name] = module
    return found


def label(name: str) -> str:
    return MODULE_LABELS.get(name, name)
