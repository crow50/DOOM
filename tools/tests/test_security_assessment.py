"""Adversarial tests for evidence accounting and the release gate."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security_assessment as assessment
from export_security_evidence import decode_pages


class AssessmentTests(unittest.TestCase):
    def mutate(self, filename, change):
        original = assessment.read
        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).name == filename:
                value = copy.deepcopy(value)
                change(value)
            return value
        with patch.object(assessment, 'read', side_effect=changed):
            return assessment.validate()

    def test_repository_evidence_is_consistent(self):
        self.assertEqual([], assessment.validate())

    def test_an_evidence_file_nobody_cites_is_rejected(self):
        """An orphan is not harmless: it looks like something rests on it."""
        orphan = assessment.ROOT / assessment.BASE / 'evidence' / 'orphan-probe.log'
        orphan.write_text('nothing points at this\n')
        try:
            errors = assessment.validate()
        finally:
            orphan.unlink()
        self.assertTrue(
            any('orphan-probe.log' in e and 'nothing cites' in e for e in errors),
            errors[:5],
        )

    def test_citing_an_evidence_file_from_prose_is_enough(self):
        """A document that argues from a file cites it as surely as a row does."""
        cited = assessment.unreferenced_evidence(
            {f'{assessment.BASE}/evidence/candidate-sbom.json'}
        )
        self.assertNotIn('evidence/candidate-sbom.json', cited)

    def test_a_raw_export_needs_no_citation(self):
        """The validator reads these itself; nothing argues from them."""
        self.assertEqual([], [
            name for name in assessment.RAW_EXPORTS
            if name in assessment.unreferenced_evidence(set())
        ])

    def test_missing_control_is_rejected(self):
        errors = self.mutate('asvs-5.0.0.json', lambda d: d['requirements'].pop(0))
        self.assertTrue(any('missing' in e for e in errors))

    def test_duplicate_control_is_rejected(self):
        errors = self.mutate('asvs-5.0.0.json', lambda d: d['requirements'].append(d['requirements'][0]))
        self.assertTrue(any('duplicate row' in e for e in errors))

    def test_unsupported_met_evidence_is_rejected(self):
        def change(d):
            d['requirements'][0].update(status='Met', evidence=['missing-evidence'])
        self.assertTrue(any('missing/unsafe evidence' in e for e in self.mutate('asvs-5.0.0.json', change)))

    def test_omitted_alert_is_rejected(self):
        errors = self.mutate('alerts.json', lambda d: d['alerts'].pop())
        self.assertIn('alert export/register mismatch', errors)

    def test_exception_cannot_be_invented(self):
        errors = self.mutate('alerts.json', lambda d: d['alerts'][0].update(exception='not-approved'))
        self.assertTrue(any('invalid exception' in e for e in errors))

    def test_unreviewed_release_fails(self):
        self.assertTrue(assessment.validate(release=True))

    def test_release_requires_all_checks_and_all_sources(self):
        original = assessment.read
        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).name == 'verification.json':
                value['checks'] = []
                value['source_hashes'] = {}
            return value
        with patch.object(assessment, 'read', side_effect=changed):
            errors = assessment.validate(release=True)
        self.assertIn('missing required verification checks', errors)
        self.assertIn('candidate source hashes absent', errors)

    def test_publication_requires_reviewed_registry_artifact(self):
        errors = assessment.validate(publish=True)
        self.assertIn('publication requires an immutable reviewed registry reference', errors)

    def test_compose_is_bound_to_candidate_evidence(self):
        self.assertIn('docker-compose.yml', assessment.source_hashes())

    def test_grouped_candidate_hashes_still_verify(self):
        verification = assessment.read('docs/security/verification.json')
        hashes = assessment.source_hashes()
        for path, digest in verification['source_hashes'].items():
            self.assertIsInstance(digest, list, path)
            self.assertEqual(32, len(digest), path)
            self.assertTrue(all(type(byte) is int and 0 <= byte <= 255 for byte in digest), path)
            self.assertEqual(hashes[path], bytes(digest).hex(), path)

    def test_source_scan_cannot_be_deferred_as_future_hosting(self):
        original = assessment.read
        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).name == 'verification.json':
                for check in value['checks']:
                    if check['name'] == 'semgrep':
                        check['scope'] = 'non-local'
            return value
        with patch.object(assessment, 'read', side_effect=changed):
            errors = assessment.validate(release=True)
        self.assertIn('semgrep: mandatory check cannot be deferred to non-local hosting', errors)

    def test_new_exported_alert_requires_reconciliation(self):
        original = assessment.read
        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).parent.name == 'updated-main' and Path(path).name == 'code-scanning-pages.json':
                value.append([{'number': 999999}])
            return value
        with patch.object(assessment, 'read', side_effect=changed):
            errors = assessment.validate()
        self.assertIn('code-scanning: refreshed alerts missing from register', errors)

    def test_textual_asvs_levels_are_required(self):
        reqs = assessment.universe('4.0.3')
        self.assertEqual(2, reqs['v4.0.3-2.10.1']['level'])
        self.assertEqual(1, reqs['v4.0.3-3.3.2']['level'])
        self.assertEqual(3, reqs['v4.0.3-2.8.7']['level'])

    def test_paginated_json_keeps_every_page(self):
        self.assertEqual([[{'number': 1}], [{'number': 2}], []],
                         decode_pages('[{"number":1}]\n[{"number":2}]\n[]'))
        with self.assertRaises(ValueError):
            decode_pages('{"message":"forbidden"}')
        with self.assertRaises(ValueError):
            decode_pages('')


if __name__ == '__main__':
    unittest.main()
