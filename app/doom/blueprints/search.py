"""Global search across items and locations.

Search is the primary way to find things here, not the tree. You cannot
navigate a hierarchy you could not face building — recall is the weak channel,
recognition is the strong one — so the search field lives in the masthead on
every screen rather than on one page.

**Ownership scoping is the load-bearing part (T-44).** Locations carry site
addresses (D-24), so a search that widened scope would be worse than no search.
Both halves start from ``owned_query()`` and ranking never relaxes the filter.
"""

from __future__ import annotations

import logging

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import func, or_, select

from .. import validation as v
from ..extensions import db, limiter
from ..models import Attachment, DocLink, Item, Location
from ..security.authz import owned_query

logger = logging.getLogger(__name__)

bp = Blueprint("search", __name__)


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_items(term: str, limit: int = None):
    """Find items by text, barcode, attached filename or linked document.

    Uses Postgres full-text search with a **bound parameter**:
    ``websearch_to_tsquery`` lets the database parse the user's search syntax
    instead of us escaping wildcards by hand, which is both better search and
    one less place to get quoting wrong (CWE-89).

    Short terms fall back to ILIKE so "dri" still finds the drill — full-text
    search matches whole lexemes and would return nothing for a prefix.
    """
    limit = limit or v.SEARCH_RESULT_LIMIT
    query = owned_query(Item)
    term = term.strip()[: v.SEARCH_QUERY_MAX]

    pattern = f"%{_escape_like(term)}%"
    like = or_(
        Item.name.ilike(pattern, escape="\\"),
        func.coalesce(Item.description, "").ilike(pattern, escape="\\"),
        func.coalesce(Item.barcode, "").ilike(pattern, escape="\\"),
        Item.id.in_(
            select(Attachment.item_id).where(
                Attachment.item_id.is_not(None),
                Attachment.original_name.ilike(pattern, escape="\\"),
            )
        ),
        Item.id.in_(
            select(DocLink.item_id).where(
                DocLink.item_id.is_not(None),
                DocLink.label.ilike(pattern, escape="\\"),
            )
        ),
    )

    if len(term) >= v.SEARCH_MIN_FTS_LENGTH:
        # Must match ix_items_fts exactly, or the index is not used.
        vector = func.to_tsvector(
            "english",
            func.coalesce(Item.name, "").concat(" ")
            .concat(func.coalesce(Item.description, "")).concat(" ")
            .concat(func.coalesce(Item.barcode, "")),
        )
        tsquery = func.websearch_to_tsquery("english", term)
        return db.session.execute(
            query.where(or_(vector.op("@@")(tsquery), like))
            .order_by(func.ts_rank(vector, tsquery).desc(), Item.name)
            .limit(limit)
        ).scalars().all()

    return db.session.execute(
        query.where(like).order_by(Item.name).limit(limit)
    ).scalars().all()


def search_locations(term: str, limit: int = None):
    """Find locations by name, notes or address.

    The address is searchable **by its owner only** — it is the most sensitive
    field in the schema (D-24) and never leaves this ownership-filtered query.
    """
    limit = limit or v.SEARCH_RESULT_LIMIT
    query = owned_query(Location)
    term = term.strip()[: v.SEARCH_QUERY_MAX]

    pattern = f"%{_escape_like(term)}%"
    like = or_(
        Location.name.ilike(pattern, escape="\\"),
        func.coalesce(Location.notes, "").ilike(pattern, escape="\\"),
        func.coalesce(Location.address, "").ilike(pattern, escape="\\"),
    )

    if len(term) >= v.SEARCH_MIN_FTS_LENGTH:
        # Must match ix_locations_fts exactly.
        vector = func.to_tsvector(
            "english",
            func.coalesce(Location.name, "").concat(" ")
            .concat(func.coalesce(Location.notes, "")).concat(" ")
            .concat(func.coalesce(Location.address, "")),
        )
        tsquery = func.websearch_to_tsquery("english", term)
        return db.session.execute(
            query.where(or_(vector.op("@@")(tsquery), like))
            .order_by(func.ts_rank(vector, tsquery).desc(), Location.name)
            .limit(limit)
        ).scalars().all()

    return db.session.execute(
        query.where(like).order_by(Location.name).limit(limit)
    ).scalars().all()


@bp.route("/search")
@login_required
@limiter.limit(v.WRITE_RATE_LIMIT)
def index():
    term = (request.args.get("q") or "").strip()[: v.SEARCH_QUERY_MAX]

    if not term:
        return render_template("search.html", term="", items=[], locations=[])

    # A barcode typed or scanned into the search box goes straight to the item.
    # Note what does NOT happen: nothing is fetched, and nothing is navigated
    # to on the strength of a scanned value (T-43).
    items = search_items(term)
    locations = search_locations(term)

    return render_template(
        "search.html", term=term, items=items, locations=locations
    )
