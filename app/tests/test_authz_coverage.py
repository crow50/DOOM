"""Ownership enforcement, checked across every route rather than asserted.

``docs/COMPLIANCE.md`` used to answer ASVS 4.2.1 with "No IDOR" and point at
``get_owned_or_404()``.  A helper existing proves nothing about the routes that
forget to call it, and an audit said so.  This module replaces the claim with two
checks that can fail:

* :class:`TestEveryEndpointIsClassified` walks ``app.url_map`` and requires every
  endpoint to be accounted for by name, with its scoping mechanism recorded.  A
  new route is a failure until someone says which mechanism protects it, so the
  mapping cannot quietly fall behind the code the way the documentation did.

* :class:`TestCrossAccountAccess` signs in as bob and asks for alice's objects
  through every route that takes an object id.  This is the property 4.2.1
  actually describes, and it does not care how any given view is implemented.
"""

from __future__ import annotations

import inspect

import pytest
from conftest import login

from doom.extensions import db
from doom.models import Attachment, DocLink

# --- scoping mechanisms -------------------------------------------------------

VETTED = "vetted"           # calls get_owned_or_404 / get_owned_for_update / owned_query
DELEGATED = "delegated"     # calls a module-level query builder that does
HAND_ROLLED = "hand-rolled"  # writes the ownership predicate inline
NO_OBJECT = "no-object"     # reaches no user-owned row addressed by the request
CAPABILITY = "capability"   # deliberately unauthenticated, guarded by a token

VETTED_HELPERS = ("get_owned_or_404", "get_owned_for_update", "owned_query")

#: Every endpoint in the application and what stops it serving someone else's
#: row.  The comment on a non-vetted entry is the justification; a reviewer
#: disagreeing with one of those six is the point of writing them down.
SCOPING: dict[str, str] = {
    "static": NO_OBJECT,

    "main.index": NO_OBJECT,
    "main.healthz": NO_OBJECT,
    "main.robots": NO_OBJECT,

    "auth.register": NO_OBJECT,
    "auth.login": NO_OBJECT,
    "auth.change_password": NO_OBJECT,          # acts on current_user only
    # Reads a UserSession by an id that came from this visitor's own signed
    # cookie, then still compares user_id before revoking it.
    "auth.logout": HAND_ROLLED,

    # The account pages are scoped by user_id / actor_user_id rather than
    # owner_id, because UserSession and AuditLog have no owner_id column - the
    # helper is inapplicable to them by construction.
    "account.profile": HAND_ROLLED,
    "account.revoke_session": HAND_ROLLED,
    "account.activity": HAND_ROLLED,
    "account.export_csv": HAND_ROLLED,

    "locations.index": VETTED,
    "locations.detail": VETTED,
    "locations.create": VETTED,                 # parent id is checked
    "locations.edit": VETTED,
    "locations.delete": VETTED,
    "locations.add_link": VETTED,
    "locations.delete_link": VETTED,            # parent checked, link id coerced

    "items.index": VETTED,
    "items.detail": VETTED,
    "items.barcode_lookup": VETTED,
    "items.quick": VETTED,
    "items.file_item": VETTED,
    "items.create": VETTED,
    "items.edit": VETTED,
    "items.adjust": VETTED,
    "items.move": VETTED,                       # both ends checked
    "items.checkout": VETTED,                   # get_owned_for_update
    "items.check_in": VETTED,
    "items.delete": VETTED,
    "items.add_link": VETTED,
    "items.delete_link": VETTED,

    "labels.label": VETTED,
    "labels.sheet": VETTED,
    "labels.rotate": VETTED,

    "files.upload": VETTED,
    "files.download": VETTED,
    "files.thumbnail": VETTED,
    "files.delete": VETTED,

    # Listing is scoped inline; registration goes through the helper.
    "nfc.index": HAND_ROLLED,
    "nfc.register": VETTED,

    # index() delegates to search_items()/search_locations(), both of which
    # start from owned_query() - see the module docstring in search.py.
    "search.index": DELEGATED,

    # The token is the credential (T-36). Unauthenticated by design, and the
    # response is built from a reduced dict with no owner in it.
    "share.view": CAPABILITY,
}


class TestEveryEndpointIsClassified:
    def test_no_endpoint_is_unaccounted_for(self, app):
        """A new route must be classified before it can ship.

        This is the check that makes the 4.2.1 claim maintainable: without it,
        adding a view that queries by id and forgets the ownership predicate
        breaks nothing and no test notices.
        """
        live = {rule.endpoint for rule in app.url_map.iter_rules()}
        unclassified = sorted(live - set(SCOPING))
        removed = sorted(set(SCOPING) - live)

        assert not unclassified, (
            "these endpoints are not in SCOPING - record how each one is scoped: "
            f"{unclassified}"
        )
        assert not removed, (
            f"SCOPING names endpoints that no longer exist: {removed}"
        )

    @pytest.mark.parametrize(
        "endpoint",
        sorted(name for name, how in SCOPING.items() if how == VETTED),
    )
    def test_vetted_endpoints_still_call_a_helper(self, app, endpoint):
        """A route classified as vetted must actually use the vetted mechanism."""
        source = inspect.getsource(app.view_functions[endpoint])
        assert any(helper in source for helper in VETTED_HELPERS), (
            f"{endpoint} is classified {VETTED!r} but calls none of "
            f"{VETTED_HELPERS}"
        )

    def test_delegated_endpoints_reach_a_helper_in_their_module(self, app):
        for endpoint, how in SCOPING.items():
            if how != DELEGATED:
                continue
            module = inspect.getmodule(app.view_functions[endpoint])
            source = inspect.getsource(module)
            assert any(helper in source for helper in VETTED_HELPERS), (
                f"{endpoint} delegates, but its module calls no vetted helper"
            )


class TestCrossAccountAccess:
    """bob asks for alice's objects, through every route that takes an id."""

    @staticmethod
    def _paths(item_id, location_id, attachment_id, link_id, checkout_id):
        """(method, path) for every route addressing a specific object."""
        return [
            ("GET", f"/items/{item_id}"),
            ("GET", f"/items/{item_id}/edit"),
            ("POST", f"/items/{item_id}/edit"),
            ("POST", f"/items/{item_id}/adjust"),
            ("POST", f"/items/{item_id}/move"),
            ("POST", f"/items/{item_id}/checkout"),
            ("POST", f"/items/{item_id}/return/{checkout_id}"),
            ("POST", f"/items/{item_id}/delete"),
            ("POST", f"/items/{item_id}/links"),
            ("POST", f"/items/{item_id}/links/{link_id}/delete"),
            ("POST", f"/items/{item_id}/file"),
            ("GET", f"/locations/{location_id}"),
            ("GET", f"/locations/{location_id}/edit"),
            ("POST", f"/locations/{location_id}/edit"),
            ("POST", f"/locations/{location_id}/delete"),
            ("POST", f"/locations/{location_id}/links"),
            ("POST", f"/locations/{location_id}/links/{link_id}/delete"),
            ("GET", f"/files/{attachment_id}"),
            ("GET", f"/files/{attachment_id}/thumb"),
            ("POST", f"/files/{attachment_id}/delete"),
            ("POST", f"/files/upload/item/{item_id}"),
            ("GET", f"/labels/item/{item_id}"),
            ("POST", f"/labels/item/{item_id}/rotate"),
            # labels.sheet takes repeatable ?location= / ?item=, which is what
            # templates/labels/label.html builds. Getting the parameter name
            # wrong makes the selection empty, and an empty sheet redirects
            # rather than 404s - so the wrong name silently tests nothing.
            ("GET", f"/labels/sheet?location={location_id}"),
            ("GET", f"/labels/sheet?item={item_id}"),
            ("POST", f"/nfc/register/item/{item_id}"),
        ]

    def test_bob_gets_404_everywhere(
        self, client, alice, bob, alice_item, alice_bin
    ):
        attachment = Attachment(
            owner_id=alice.id,
            item_id=alice_item.id,
            kind="photo",
            stored_name="deadbeef.jpg",
            thumbnail_name="deadbeef-thumb.jpg",
            original_name="photo.jpg",
            content_type="image/jpeg",
            byte_size=1024,
            sha256="0" * 64,
        )
        link = DocLink(item_id=alice_item.id, label="manual", url="https://example.invalid/m")
        db.session.add_all([attachment, link])
        db.session.commit()

        paths = self._paths(
            alice_item.id, alice_bin.id, attachment.id, link.id, alice_item.id
        )

        login(client, "bob")

        leaked = []
        for method, path in paths:
            response = client.open(path, method=method)
            # 404 is the required answer. 405 means the route does not accept
            # this verb, which is fine; anything else is a leak or a crash.
            if response.status_code not in (404, 405):
                leaked.append((method, path, response.status_code))

        assert not leaked, f"cross-account access did not 404: {leaked}"
