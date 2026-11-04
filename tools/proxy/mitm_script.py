"""Entry point for `mitmdump -s`.

mitmproxy executes script files outside the normal import system, which breaks dataclasses in
the script itself. This file only imports the addon as a regular package module (PYTHONPATH
must contain the repository root, or /app in the tools image).
"""

from tools.proxy.addon import create_addons

addons = create_addons()
