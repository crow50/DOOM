#!/usr/bin/env python3
"""Read all GitHub alert pages without exporting secret values.

Requires an authenticated gh CLI. Does not dismiss alerts or change the repo.
Use a fresh directory for each capture; partial exports are never called complete.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess


def decode_pages(raw):
    pages = []
    decoder = json.JSONDecoder()
    while raw.strip():
        page, offset = decoder.raw_decode(raw.lstrip())
        if not isinstance(page, list):
            raise ValueError("Expected an alert/analysis array")
        pages.append(page)
        raw = raw.lstrip()[offset:]
    if not pages:
        raise ValueError("Missing API response; an empty alert list must be []")
    return pages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="crow50/DOOM")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, endpoint in (("code-scanning", "code-scanning/alerts"),
                           ("analyses", "code-scanning/analyses"),
                           ("dependabot", "dependabot/alerts"),
                           ("secret-scanning", "secret-scanning/alerts")):
        try:
            result = subprocess.run(
                ["gh", "api", "--paginate", f"repos/{args.repo}/{endpoint}?per_page=100"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode:
                sources[name] = {"available": False, "error": result.stderr.strip()}
                continue
            pages = decode_pages(result.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            # Do not stringify TimeoutExpired: it may include partial output
            # from the secret-scanning endpoint.
            sources[name] = {"available": False, "error": type(exc).__name__}
            continue
        sources[name] = {"available": True}
        if name == "secret-scanning":
            # Never persist secret, location contents, or validity-check data.
            allowed = {"number", "state", "secret_type", "created_at", "resolved_at", "resolution"}
            pages = [[{k: v for k, v in row.items() if k in allowed} for row in page]
                     for page in pages]
        sources[name]["count"] = sum(map(len, pages))
        (args.output / f"{name}-pages.json").write_text(json.dumps(pages, indent=2) + "\n")
    sources["captured_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    (args.output / "source-availability.json").write_text(json.dumps(sources, indent=2) + "\n")
    return int(any(not value["available"] for value in sources.values() if isinstance(value, dict)))


if __name__ == "__main__":
    raise SystemExit(main())
