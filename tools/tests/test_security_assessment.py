"""Adversarial tests for the ledger validator.

Each one breaks something and asserts the validator notices. The tests that
used to live here checked the bookkeeping this repository no longer keeps -
that a committed snapshot of GitHub's alert API agreed with a committed
register derived from it, that a SHA-256 manifest of every source file matched
the tree, that no file in an evidence directory went uncited. All three
compared self-attested records against each other, and D-40 records why they
went with the records.
"""
import contextlib
import copy
import datetime as dt
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security_assessment as assessment
from export_security_evidence import decode_pages


class LedgerTests(unittest.TestCase):
    """Break the ASVS ledger; expect a specific complaint."""

    def mutate(self, filename, change, **kwargs):
        original = assessment.read

        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).name == filename:
                value = copy.deepcopy(value)
                change(value)
            return value

        with patch.object(assessment, "read", side_effect=changed):
            return assessment.validate(**kwargs)

    def ledger(self, change, **kwargs):
        return self.mutate(f"asvs-{assessment.VERSION}.json", change, **kwargs)

    def findings(self, change, **kwargs):
        return self.mutate("findings.json", change, **kwargs)

    def assertComplains(self, errors, fragment):
        self.assertTrue(any(fragment in e for e in errors),
                        f"expected a complaint containing {fragment!r}, got {errors[:4]}")

    # --- the repository as it stands ---------------------------------------
    def test_the_repository_is_consistent(self):
        self.assertEqual([], assessment.validate())

    def test_every_mandatory_requirement_has_a_row(self):
        official = assessment.universe()
        rows = {r["id"] for r in
                assessment.read(assessment.BASE / f"asvs-{assessment.VERSION}.json")["requirements"]}
        mandatory = {rid for rid, row in official.items() if row["level"] <= 2}
        self.assertEqual(set(), mandatory - rows)

    # --- coverage ----------------------------------------------------------
    def test_a_dropped_requirement_is_rejected(self):
        self.assertComplains(self.ledger(lambda d: d["requirements"].pop(0)), "missing mandatory")

    def test_a_duplicated_requirement_is_rejected(self):
        self.assertComplains(
            self.ledger(lambda d: d["requirements"].append(d["requirements"][0])),
            "appears more than once")

    def test_an_invented_requirement_is_rejected(self):
        def change(d):
            d["requirements"][0]["id"] = "v5.0.0-99.99.99"
        self.assertComplains(self.ledger(change), "not a requirement in ASVS")

    def test_reworded_requirement_text_is_rejected(self):
        """The row has to quote the standard, not paraphrase it."""
        def change(d):
            d["requirements"][0]["requirement"] += " (and also whatever we happened to build)"
        self.assertComplains(self.ledger(change), "verbatim")

    def test_a_row_moved_to_a_easier_level_is_rejected(self):
        def change(d):
            row = next(r for r in d["requirements"] if r["level"] == 2)
            row["level"] = 3
        self.assertComplains(self.ledger(change), "wrong level")

    # --- a status has to be supported --------------------------------------
    def test_met_without_evidence_that_exists_is_rejected(self):
        def change(d):
            d["requirements"][0].update(status="Met", evidence=["app/doom/imaginary.py"])
        self.assertComplains(self.ledger(change), "evidence does not exist")

    def test_a_status_without_a_rationale_is_rejected(self):
        def change(d):
            d["requirements"][0]["rationale"] = ""
        self.assertComplains(self.ledger(change), "assertion")

    def test_an_evidence_line_past_the_end_of_the_file_is_rejected(self):
        def change(d):
            d["requirements"][0].update(status="Met", evidence=["app/doom/config.py:99999"])
        self.assertComplains(self.ledger(change), "line out of range")

    def test_evidence_outside_the_repository_is_rejected(self):
        def change(d):
            d["requirements"][0].update(status="Met", evidence=["../../etc/passwd"])
        self.assertComplains(self.ledger(change), "evidence does not exist")

    def test_a_level_three_row_needs_its_threat_stated(self):
        def change(d):
            row = next(r for r in d["requirements"] if r["level"] == 3)
            row["selection_reason"] = ""
        self.assertComplains(self.ledger(change), "Level 3")

    # --- a gap has to be owned ---------------------------------------------
    def test_a_gap_with_no_finding_is_rejected(self):
        def change(d):
            d["requirements"][0].update(status="Not met", finding_ids=[])
        self.assertComplains(self.ledger(change), "nobody owns")

    def test_a_gap_pointing_at_a_nonexistent_finding_is_rejected(self):
        def change(d):
            d["requirements"][0].update(status="Not met", finding_ids=["CONTROL-nope"])
        self.assertComplains(self.ledger(change), "does not exist")

    def test_a_gap_whose_finding_is_closed_is_rejected(self):
        """Closing the finding without closing the row is how a gap disappears."""
        def change(d):
            row = next(r for r in d["requirements"] if r["status"] == "Not met")
            row["finding_ids"] = ["REV-001"]
        self.assertComplains(self.ledger(change), "is closed")

    def test_risk_acceptance_cannot_be_written_into_a_status(self):
        def change(d):
            d["requirements"][0]["exception"] = "we decided it was fine"
        self.assertComplains(self.ledger(change), "belongs in the finding register")

    def test_stale_totals_are_rejected(self):
        def change(d):
            d["totals"]["Met"] += 1
        self.assertComplains(self.ledger(change), "totals")

    # --- findings ----------------------------------------------------------
    def test_a_finding_without_a_residual_risk_is_rejected(self):
        def change(f):
            f[0]["residual_risk"] = "probably fine"
        self.assertComplains(self.findings(change), "invalid residual risk")

    def test_a_closed_finding_carrying_risk_is_rejected(self):
        def change(f):
            closed = next(x for x in f if x["status"] == "closed")
            closed["residual_risk"] = "medium"
        self.assertComplains(self.findings(change), "still carries residual risk")

    def test_a_finding_missing_its_remediation_is_rejected(self):
        def change(f):
            f[0]["remediation"] = ""
        self.assertComplains(self.findings(change), "missing remediation")

    def test_duplicate_finding_ids_are_rejected(self):
        self.assertComplains(self.findings(lambda f: f.append(f[0])), "duplicate finding id")

    # --- the release gate ---------------------------------------------------
    def test_release_refuses_an_unassessed_requirement(self):
        def change(d):
            d["requirements"][0]["status"] = "Not assessed"
        self.assertComplains(self.ledger(change, release=True), "never assessed")

    def test_release_refuses_an_open_risk_nobody_accepted(self):
        def change(exceptions):
            exceptions.clear()
        self.assertComplains(self.mutate("exceptions.json", change, release=True),
                              "nobody has accepted")

    def test_release_refuses_an_open_high_risk(self):
        def change(f):
            f[0]["residual_risk"] = "high"
        self.assertComplains(self.findings(change, release=True), "high residual risk")

    def test_publication_requires_a_reviewed_immutable_artifact(self):
        def change(c):
            c["registry_ref"] = None
            c["image_id"] = None
        errors = self.mutate("release-candidate.json", change, publish=True)
        self.assertComplains(errors, "immutable, reviewed")

    def test_publication_refuses_a_mutable_tag(self):
        def change(c):
            c["registry_ref"] = "ghcr.io/crow50/doom-organizer:latest"
            c["image_id"] = "sha256:" + "a" * 64
        errors = self.mutate("release-candidate.json", change, publish=True)
        self.assertComplains(errors, "immutable, reviewed")

    # --- the vendored standard ---------------------------------------------
    def test_a_modified_standard_is_rejected(self):
        def change(entries):
            entries[0]["sha256"] = "0" * 64
        self.assertComplains(self.mutate("standards.json", change), "has changed")

    def test_the_standard_and_its_licence_must_both_be_recorded(self):
        def change(entries):
            del entries[0]
        self.assertComplains(self.mutate("standards.json", change), "must record")

    def test_textual_asvs_levels_are_parsed_as_integers(self):
        official = assessment.universe()
        self.assertTrue(all(row["level"] in (1, 2, 3) for row in official.values()))
        self.assertGreater(len([r for r in official.values() if r["level"] <= 2]), 250)


class ExpiryTests(unittest.TestCase):
    """An exception's expiry is checked against the clock, so hold the clock still.

    The clock is the one input to the validator that changes with no commit. As
    an error on every branch, a lapsed exception took `lint-and-compile` red on
    every unrelated pull request on 2026-10-27, and no test noticed because none
    covered expiry at all. Every test here passes `today`, so none of them can
    start failing on its own as the real date moves.
    """

    TODAY = dt.date(2026, 11, 3)

    def patched_exceptions(self, change):
        """Pass exceptions.json through `change`, a function that edits a copy."""
        original = assessment.read

        def changed(path, root=assessment.ROOT):
            value = original(path, root)
            if Path(path).name == "exceptions.json":
                value = copy.deepcopy(value)
                change(value)
            return value

        return patch.object(assessment, "read", side_effect=changed)

    def errors(self, expires, **kwargs):
        """Validate the real repository with its first exception expiring on `expires`."""
        def change(rows):
            rows[0]["expires"] = expires
        with self.patched_exceptions(change):
            return assessment.validate(today=self.TODAY, **kwargs)

    def expired(self, errors):
        return [e for e in errors if e.endswith(": expired")]

    def test_a_lapsed_exception_does_not_fail_an_ordinary_branch(self):
        self.assertEqual([], self.errors("2026-10-27"))

    def test_a_lapsed_exception_still_blocks_a_release(self):
        self.assertEqual(1, len(self.expired(self.errors("2026-10-27", release=True))))

    def test_a_lapsed_exception_still_blocks_publishing(self):
        self.assertEqual(1, len(self.expired(self.errors("2026-10-27", publish=True))))

    def test_the_expiry_date_itself_counts_as_expired(self):
        self.assertEqual(1, len(self.expired(self.errors("2026-11-03", release=True))))
        self.assertEqual([], self.expired(self.errors("2026-11-04", release=True)))

    def test_an_unusable_expiry_is_an_error_everywhere(self):
        """A garbled or missing date is bookkeeping, not the clock: it never passes."""
        for bad in ("next tuesday", ""):
            with self.subTest(expires=bad):
                errors = self.errors(bad)
                self.assertEqual(1, len([e for e in errors if "invalid or missing expiry" in e]))

        def drop(rows):
            del rows[0]["expires"]
        with self.patched_exceptions(drop):
            errors = assessment.validate(today=self.TODAY)
        self.assertEqual(1, len([e for e in errors if "invalid or missing expiry" in e]))

    # --- the notices that replace the error outside a release --------------
    def notices(self, expiries, **kwargs):
        def change(rows):
            rows[:] = [{"id": f"EXC-{n}", "expires": expires}
                       for n, expires in enumerate(expiries)]
        with self.patched_exceptions(change):
            return assessment.expiry_notices(today=self.TODAY, **kwargs)

    def test_a_lapsed_exception_is_reported(self):
        (notice,) = self.notices(["2026-10-27"])
        self.assertIn("EXC-0: expired 7 day(s) ago", notice)

    def test_an_exception_lapsing_today_is_reported_as_expired(self):
        (notice,) = self.notices(["2026-11-03"])
        self.assertIn("counts as expired from now", notice)

    def test_an_exception_lapsing_soon_is_reported_ahead_of_time(self):
        (notice,) = self.notices(["2026-11-20"], within=30)
        self.assertIn("expires in 17 day(s)", notice)

    def test_an_exception_far_from_expiry_is_not_reported(self):
        self.assertEqual([], self.notices(["2027-01-01"], within=30))  # 59 days out

    def test_the_boundary_of_the_notice_window_is_inclusive(self):
        self.assertEqual(1, len(self.notices(["2026-12-03"], within=30)))  # exactly 30 days
        self.assertEqual([], self.notices(["2026-12-04"], within=30))      # 31 days

    def test_the_soonest_is_listed_first(self):
        notices = self.notices(["2026-11-20", "2026-10-27", "2026-11-10"], within=30)
        self.assertEqual(["EXC-1", "EXC-2", "EXC-0"], [n.split(":")[0] for n in notices])

    def test_an_unusable_date_is_skipped_here_and_left_to_validate(self):
        self.assertEqual([], self.notices(["not a date", ""]))

    # --- the scheduled check ------------------------------------------------
    def run_main(self, *argv):
        out = io.StringIO()
        with patch.object(sys, "argv", ["security_assessment.py", *argv]), \
                contextlib.redirect_stdout(out):
            failed = assessment.main()
        return failed, out.getvalue()

    def test_the_scheduled_check_fails_when_something_is_expiring(self):
        with patch.object(assessment, "expiry_notices",
                          return_value=["EXC-X: expires in 3 day(s) (2026-11-06)"]) as notices:
            failed, output = self.run_main("--expiring-within", "30")
        notices.assert_called_once_with(within=30)
        self.assertTrue(failed)
        self.assertIn("FAIL: EXC-X", output)

    def test_the_scheduled_check_passes_when_nothing_is(self):
        with patch.object(assessment, "expiry_notices", return_value=[]):
            failed, output = self.run_main("--expiring-within", "30")
        self.assertFalse(failed)
        self.assertIn("No exception has lapsed", output)


class PaginationTests(unittest.TestCase):
    def test_every_page_of_a_concatenated_export_is_kept(self):
        """A GitHub export arrives as concatenated JSON documents, not one array."""
        pages = decode_pages('[{"number": 1}]\n[{"number": 2}]\n')
        self.assertEqual([[{"number": 1}], [{"number": 2}]], pages)


if __name__ == "__main__":
    unittest.main()
