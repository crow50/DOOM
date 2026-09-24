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

    def test_unreviewed_package_or_distro_change_fails_closed(self):
        for component, expected in (
            ({"version": "1.3.2-r1"}, "unexpected zlib version"),
            ({"purl": "pkg:apk/alpine/zlib@1.3.2-r0?arch=x86_64&distro=alpine-3.24.0"}, "unexpected Alpine release"),
        ):
            with self.subTest(expected=expected):
                sbom = {"components": [{**self.sbom["components"][0], **component}]}
                with self.assertRaisesRegex(ValueError, expected):
                    document(sbom)


if __name__ == "__main__":
    unittest.main()
