"""The zlib VEX generator must match only the reviewed runtime package."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_runtime_vex import VULNERABILITY, document


class RuntimeVexTests(unittest.TestCase):
    def setUp(self):
        self.sbom = {
            "components": [
                {
                    "type": "library",
                    "name": "zlib",
                    "version": "1.3.2-r0",
                    "purl": (
                        "pkg:apk/alpine/zlib@1.3.2-r0?arch=x86_64&"
                        "distro=alpine-3.23.6"
                    ),
                }
            ]
        }

    def test_statement_is_fixed_for_exact_candidate_purl(self):
        vex = document(self.sbom, "2026-09-24T00:00:00Z")
        statement = vex["statements"][0]
        self.assertEqual(VULNERABILITY, statement["vulnerability"]["name"])
        self.assertEqual("fixed", statement["status"])
        self.assertEqual(
            self.sbom["components"][0]["purl"], statement["products"][0]["@id"]
        )
        self.assertIn("df84af25dc1942490e1d1c899a07619152a46148", statement["impact_statement"])

    def test_an_alpine_revision_bump_of_the_reviewed_upstream_release_is_covered(self):
        """`apk upgrade` moves zlib from -r0 to -r1 with no change in this repository.

        This used to fail closed on "1.3.2-r1", which is what turned the image
        scans red on main and every branch at once. The revision is a packaging
        detail of the same upstream release the replacement library is built from.
        """
        purl = "pkg:apk/alpine/zlib@1.3.2-r1?arch=x86_64&distro=alpine-3.23.7"
        sbom = {"components": [{**self.sbom["components"][0], "version": "1.3.2-r1", "purl": purl}]}
        statement = document(sbom, "2026-10-12T00:00:00Z")["statements"][0]
        self.assertEqual(purl, statement["products"][0]["@id"])
        self.assertIn("Alpine zlib 1.3.2-r1", statement["impact_statement"])
        self.assertNotIn("1.3.2-r0", statement["impact_statement"])

    def test_unreviewed_package_or_distro_change_fails_closed(self):
        for component, expected in (
            # A different UPSTREAM release changes what the statement is about.
            ({"version": "1.3.3-r0"}, "unexpected zlib version"),
            ({"version": "1.3.20-r0"}, "unexpected zlib version"),
            ({"version": "1.3.2"}, "unexpected zlib version"),
            ({"version": "1.3.2-r1-extra"}, "unexpected zlib version"),
            ({"purl": "pkg:apk/alpine/zlib@1.3.2-r0?arch=x86_64&distro=alpine-3.24.0"}, "unexpected Alpine release"),
        ):
            with self.subTest(expected=expected):
                sbom = {"components": [{**self.sbom["components"][0], **component}]}
                with self.assertRaisesRegex(ValueError, expected):
                    document(sbom)


if __name__ == "__main__":
    unittest.main()
