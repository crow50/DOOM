#!/usr/bin/env python3
"""Regenerate app/doom/security/data/common_passwords.txt.

ASVS 4.0.3 V2.1.7 asks that submitted passwords be checked against "a set of
breached passwords either locally (such as the top 1,000 or 10,000 most common
passwords **which match the system's password policy**) or using an external
API".  That emphasis is the whole reason this script exists.

DOOM requires 12 characters.  A conventional top-10,000 list is almost entirely
below that, so every entry in it is rejected by the length check before the
breach screen is ever consulted -- which is exactly what had happened: the
previous hardcoded list held 124 entries, 123 of them under 12 characters, and
the screen could only ever match the single string "administrator".

So the corpus is drawn from a 1,000,000-entry release and filtered to the policy
length **first**, then truncated to the top 10,000 by frequency rank.  Entries are
lowercased because security/passwords.py folds the candidate before comparing,
which makes each entry catch every capitalisation of itself.

Network access is needed only to regenerate; the result is committed, so builds
and tests are offline.  The source digest is recorded in the output header and
checked here, so a silently changed upstream list fails loudly instead of
quietly altering a control.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "app" / "doom" / "security" / "data" / "common_passwords.txt"

SOURCE_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"
)
#: Digest of the upstream list this corpus was last built from.  SecLists is a
#: moving target; pinning the digest means an upstream change is a visible
#: decision rather than an invisible one.
SOURCE_SHA256 = "424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51"

MIN_LENGTH = 12      # keep in step with validation.PASSWORD_MIN
MAX_LENGTH = 128     # keep in step with validation.PASSWORD_MAX
WANTED = 10_000      # the upper figure ASVS 2.1.7 names


def policy_bounds() -> tuple[int, int]:
    """Read the real bounds out of validation.py rather than trusting constants here."""
    text = (ROOT / "app" / "doom" / "validation.py").read_text(encoding="utf-8")
    found: dict[str, int] = {}
    for line in text.splitlines():
        for name in ("PASSWORD_MIN", "PASSWORD_MAX"):
            if line.startswith(f"{name} ") or line.startswith(f"{name}="):
                digits = "".join(c for c in line.split("=", 1)[1] if c.isdigit())
                if digits:
                    found[name] = int(digits)
    return found.get("PASSWORD_MIN", MIN_LENGTH), found.get("PASSWORD_MAX", MAX_LENGTH)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", help="local copy of the upstream list, instead of downloading"
    )
    parser.add_argument(
        "--allow-digest-change", action="store_true",
        help="accept a source whose digest differs from the pinned one",
    )
    args = parser.parse_args()

    if args.source:
        raw = Path(args.source).read_bytes()
    else:
        print(f"fetching {SOURCE_URL}")
        with urllib.request.urlopen(SOURCE_URL, timeout=120) as response:
            raw = response.read()

    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCE_SHA256 and not args.allow_digest_change:
        print(
            f"source digest changed.\n"
            f"  expected {SOURCE_SHA256}\n"
            f"  got      {digest}\n"
            "Upstream has been modified. Review the change, then re-run with\n"
            "--allow-digest-change and update SOURCE_SHA256 in this script.",
            file=sys.stderr,
        )
        return 1

    minimum, maximum = policy_bounds()
    seen: set[str] = set()
    kept: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        candidate = line.strip()
        if not (minimum <= len(candidate) <= maximum):
            continue
        folded = candidate.lower()
        if folded in seen:
            continue
        seen.add(folded)
        kept.append(folded)
        if len(kept) == WANTED:
            break

    if len(kept) < 1000:
        print(
            f"only {len(kept)} entries clear the {minimum}-character policy; "
            "ASVS 2.1.7 names 1,000 as the lower figure",
            file=sys.stderr,
        )
        return 1

    kept.sort()
    header = f"""\
# The top {len(kept):,} most common breached passwords that satisfy this application's
# password policy, one per line, lowercased.
#
# Why the filter matters.  ASVS 4.0.3 V2.1.7 asks for "the top 1,000 or 10,000
# most common passwords WHICH MATCH THE SYSTEM'S PASSWORD POLICY".  DOOM requires
# {minimum} characters, and almost nothing in a conventional top-10,000 list is that
# long - so a top-10,000 list would be screened out by the length check before
# this file was ever consulted, and the breach screen would do nothing.  These
# entries were therefore drawn from a 1,000,000-entry corpus and filtered to the
# {minimum}-character minimum first, which is what makes the screen reachable.
#
# Provenance:  SecLists, Passwords/Common-Credentials/
#              xato-net-10-million-passwords-1000000.txt
#              (Mark Burnett's 10M-password release, ordered by frequency)
#              source sha256 {digest}
#
# Selection:   first {len(kept):,} entries of length {minimum}-{maximum} in frequency order,
#              lowercased and de-duplicated, then sorted for reviewable diffs.
#              Regenerate with `make passwords-corpus`.
#
# Comparison is case-insensitive: security/passwords.py folds the candidate with
# str.lower() before the membership test, so an entry here also catches every
# capitalisation of itself.
"""
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(header + "\n".join(kept) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(kept):,} entries, "
          f"lengths {minimum}-{max(len(k) for k in kept)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
