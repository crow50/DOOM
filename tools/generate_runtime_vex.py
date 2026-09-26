#!/usr/bin/env python3
"""Generate the narrowly scoped VEX statement for the patched runtime zlib.

The APK database in the image intentionally remains truthful about its shipped
package version. Until Alpine publishes a fixed package, that metadata still
matches CVE-2026-85091 even though the runtime's libz has been replaced with
the upstream fix. This tool binds the statement to the exact zlib PURL in the
candidate image's SBOM and refuses unexpected package/distro changes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VULNERABILITY = "CVE-2026-85091"
ZLIB_VERSION = "1.3.2-r0"
UPSTREAM_COMMIT = "df84af25dc1942490e1d1c899a07619152a46148"
SOURCE_SHA256 = "03a76732cfaa124c58b67600699d935d081604385c03aa282f81a101b7536161"


def zlib_component(sbom: dict) -> dict:
    components = [
        component
        for component in sbom.get("components", [])
        if component.get("name", "").lower() == "zlib"
        and component.get("type") in {"library", "operating-system"}
    ]
    if len(components) != 1:
        raise ValueError(f"expected one zlib SBOM component, found {len(components)}")

    component = components[0]
    purl = component.get("purl", "")
    parsed = urlsplit(purl)
    qualifiers = parse_qs(parsed.query)
    if not purl.startswith("pkg:apk/alpine/zlib@"):
        raise ValueError(f"unexpected zlib package URL: {purl!r}")
    if component.get("version") != ZLIB_VERSION:
        raise ValueError(
            f"unexpected zlib version {component.get('version')!r}; "
            "review the VEX statement before changing the pinned condition"
        )
    if not qualifiers.get("distro", [""])[0].startswith("alpine-3.23."):
        raise ValueError(f"unexpected Alpine release in zlib package URL: {purl!r}")
    return component


def document(sbom: dict, timestamp: str | None = None) -> dict:
    component = zlib_component(sbom)
    timestamp = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    purl = component["purl"]
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:doom:security:vex:{VULNERABILITY}:{purl}",
        "author": "DOOM security review",
        "timestamp": timestamp,
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": VULNERABILITY},
                "products": [{"@id": purl}],
                "status": "fixed",
                "impact_statement": (
                    "The runtime package inventory reports Alpine zlib 1.3.2-r0, "
                    "but /usr/local/lib/libz.so.1.3.2.1-motley is built from upstream "
                    f"zlib commit {UPSTREAM_COMMIT}, whose source archive SHA-256 "
                    f"is {SOURCE_SHA256}. The Dockerfile runs the upstream test "
                    "suite and verifies that Python maps this replacement shared "
                    "object at runtime. The vulnerable implementation is therefore "
                    "not present in the library used by this image."
                ),
                "action_statement": (
                    "This statement applies only to the exact zlib package PURL "
                    "from this candidate SBOM. Remove it when the Alpine package "
                    "itself includes the upstream fix; the generator fails closed "
                    "if the distro or package version changes."
                ),
                "timestamp": timestamp,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        vex = document(sbom)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(vex, indent=2) + "\n", encoding="utf-8")
    print(f"wrote exact-PURL VEX for {VULNERABILITY}: {vex['statements'][0]['products'][0]['@id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
