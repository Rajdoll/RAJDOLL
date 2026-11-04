"""Render pages in headless Chromium and record what the application requests (SPA recon).

Run by the `browser` adapter as `python browser_crawl.py config.json`. Standalone on purpose:
only the standard library and Playwright, so the runner can start it like any other tool.
All traffic goes through the egress proxy given in the config (Playwright, unlike headless
katana, sends proxy credentials). Output is JSON lines in `out.jsonl`:

    {"type": "page", "url", "status", "title"}
    {"type": "request", "method", "url", "resource_type", "content_type", "post_data", "page"}
    {"type": "link", "url", "page", "followed"}
    {"type": "form", "method", "action", "enctype", "params", "page"}
"""

import json
import sys
from collections import deque
from pathlib import Path
from urllib.parse import urldefrag, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

MAX_POST_DATA = 2000
SKIPPED_RESOURCES = {"image", "media", "font"}

FORMS_JS = """
() => Array.from(document.forms).map(f => ({
  method: (f.getAttribute('method') || 'GET').toUpperCase(),
  action: f.action || location.href,
  enctype: f.enctype || null,
  params: Array.from(f.elements).map(e => e.name).filter(n => n)
}))
"""


def xss_check(config: dict) -> int:
    """Open each attempt (GET URL or POSTed form) and report whether alert(marker) ran."""
    out = open(config["out"], "a", encoding="utf-8")  # noqa: SIM115 (closed below)
    marker = config["marker"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            proxy=config["proxy"], args=["--disable-dev-shm-usage"]
        )
        context = browser.new_context(
            ignore_https_errors=True, extra_http_headers=config.get("headers", {})
        )
        for index, attempt in enumerate(config["attempts"]):
            page = context.new_page()
            dialogs: list[str] = []

            def on_dialog(dialog, seen=dialogs) -> None:  # type: ignore[no-untyped-def]
                seen.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", on_dialog)
            page.set_default_timeout(config.get("page_timeout_ms", 15000))
            status, error = None, None
            try:
                if attempt["method"] == "GET":
                    response = page.goto(attempt["url"], wait_until="load")
                    status = response.status if response else None
                else:
                    page.goto("about:blank")
                    with page.expect_navigation(wait_until="load") as navigation:
                        page.evaluate(SUBMIT_FORM_JS, attempt)
                    response = navigation.value
                    status = response.status if response else None
                page.wait_for_timeout(config.get("settle_ms", 1000))
            except PlaywrightError as exc:
                # Kept apart from dialogs: the message quotes the URL, which holds the marker.
                error = str(exc).splitlines()[0][:200]
            executed = any(marker in message for message in dialogs)
            out.write(
                json.dumps(
                    {
                        "type": "xss",
                        "attempt": index,
                        "status": status,
                        "dialogs": dialogs[:10],
                        "executed": executed,
                        "error": error,
                    }
                )
                + "\n"
            )
            out.flush()
            page.close()
            if executed:
                break
        browser.close()
    out.close()
    return 0


SUBMIT_FORM_JS = """
(attempt) => {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = attempt.url;
  for (const [name, value] of Object.entries(attempt.form || {})) {
    const input = document.createElement('input');
    input.type = 'hidden'; input.name = name; input.value = value;
    form.appendChild(input);
  }
  document.body.appendChild(form);
  form.submit();
}
"""


def main(config_path: str) -> int:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    if config.get("mode") == "xss":
        return xss_check(config)
    out = open(config["out"], "a", encoding="utf-8")  # noqa: SIM115 (closed below)

    def write(record: dict) -> None:
        out.write(json.dumps(record) + "\n")
        out.flush()

    hosts = {urlsplit(url).hostname for url in config["start_urls"]}
    exclude = [item.lower() for item in config.get("exclude", [])]

    def excluded(url: str) -> bool:
        return any(item in url.lower() for item in exclude)

    headers = dict(config.get("headers", {}))
    cookie_header = headers.pop("Cookie", headers.pop("cookie", ""))
    queue = deque((urldefrag(url)[0], 0) for url in config["start_urls"])
    visited: set[str] = set()
    current_page = {"url": ""}

    with sync_playwright() as playwright:
        # /dev/shm is small in containers; Chromium then uses /tmp instead.
        browser = playwright.chromium.launch(
            proxy=config["proxy"], args=["--disable-dev-shm-usage"]
        )
        context = browser.new_context(ignore_https_errors=True, extra_http_headers=headers)
        if cookie_header:
            cookies = []
            for part in cookie_header.split(";"):
                name, _, value = part.strip().partition("=")
                if name:
                    for url in config["start_urls"]:
                        cookies.append({"name": name, "value": value, "url": url})
            context.add_cookies(cookies)

        def on_request(request) -> None:  # type: ignore[no-untyped-def]
            if request.resource_type in SKIPPED_RESOURCES:
                return
            post = request.post_data
            write(
                {
                    "type": "request",
                    "method": request.method,
                    "url": request.url,
                    "resource_type": request.resource_type,
                    "content_type": request.headers.get("content-type"),
                    "post_data": post[:MAX_POST_DATA] if post else None,
                    "page": current_page["url"],
                }
            )

        def route(route) -> None:  # type: ignore[no-untyped-def]
            if route.request.resource_type in SKIPPED_RESOURCES:
                route.abort()
            else:
                route.continue_()

        page = context.new_page()
        page.on("request", on_request)
        page.route("**/*", route)
        page.set_default_timeout(config.get("page_timeout_ms", 15000))

        while queue and len(visited) < config.get("max_pages", 25):
            url, depth = queue.popleft()
            if url in visited or excluded(url) or urlsplit(url).hostname not in hosts:
                continue
            visited.add(url)
            current_page["url"] = url
            try:
                response = page.goto(url, wait_until="load")
                page.wait_for_timeout(config.get("settle_ms", 1500))
                write(
                    {
                        "type": "page",
                        "url": url,
                        "final_url": page.url,
                        "status": response.status if response else None,
                        "title": page.title(),
                    }
                )
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                forms = page.evaluate(FORMS_JS)
            except PlaywrightError as exc:
                write({"type": "page", "url": url, "status": None, "error": str(exc)[:300]})
                continue
            for form in forms:
                write({"type": "form", **form, "page": url})
            for link in links:
                link = urldefrag(link)[0]
                if not link.startswith(("http://", "https://")):
                    continue
                follow = (
                    depth < config.get("max_depth", 2)
                    and urlsplit(link).hostname in hosts
                    and not excluded(link)
                )
                write({"type": "link", "url": link, "page": url, "followed": follow})
                if follow and link not in visited:
                    queue.append((link, depth + 1))
        browser.close()
    out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
