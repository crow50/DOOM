"""Reduced views for public share pages.

The control here is *absence*, not filtering.

A shared page could be built by passing the ORM object to a template and
writing ``{% if not public %}`` around the sensitive parts.  That works until
someone adds a field to the template and forgets the guard, and the failure is
silent - the page renders, looks fine to its author, and quietly publishes the
owner's name or the warehouse the bin sits in.

Instead a share route receives one of these plain dictionaries.  The owner,
the ancestor chain, the movement ledger and the audit trail are not hidden;
they are never put in.  A template mistake cannot leak a field that was never
passed to it (T-20).

What the omissions protect:

* **owner** - who possesses these things
* **ancestors** - the chain from a bin up to a warehouse *is* the physical
  address.  A shared tote may say what is inside it, never where it stands.
* **siblings / parent links** - a shared page is a leaf, not a doorway.  One
  leaked token must never become a browsable catalogue.
* **movements** - timestamps of visits describe when a location is occupied,
  and therefore when it is not.
"""

from __future__ import annotations

from typing import Any

from ..models import Attachment, DocLink, Item, Location


def public_item(item: Item, *, attachments: list[Attachment], links: list[DocLink]) -> dict[str, Any]:
    """Everything a scanned item label may reveal, and nothing else."""
    return {
        "kind": "item",
        "name": item.name,
        "description": item.description,
        "quantity": item.quantity,
        "short_code": item.short_code,
        "photos": [
            {"id": str(a.id), "original_name": a.original_name}
            for a in attachments
            if a.kind == "photo"
        ],
        "documents": [
            {"id": str(a.id), "original_name": a.original_name}
            for a in attachments
            if a.kind == "document"
        ],
        "links": [{"label": link.label, "url": link.url} for link in links],
    }


def public_location(
    location: Location,
    *,
    items: list[Item],
    attachments: list[Attachment],
    links: list[DocLink],
) -> dict[str, Any]:
    """A shared container: what is inside it, one level down.

    Contents are listed because that is the entire point of scanning a tote.
    Each entry carries a share token only if that item is itself shared, so
    drilling in is possible where the owner allowed it and impossible where
    they did not - the parent's token never confers access to a child.
    """
    return {
        "kind": "location",
        "name": location.name,
        "location_kind": location.kind,
        "notes": location.notes,
        "short_code": location.short_code,
        "contents": [
            {
                "name": item.name,
                "quantity": item.quantity,
                # Present only when the item is separately shared. No token,
                # no link - the template renders plain text instead.
                "share_token": item.share_token if item.is_shared else None,
            }
            for item in items
        ],
        "photos": [
            {"id": str(a.id), "original_name": a.original_name}
            for a in attachments
            if a.kind == "photo"
        ],
        "documents": [
            {"id": str(a.id), "original_name": a.original_name}
            for a in attachments
            if a.kind == "document"
        ],
        "links": [{"label": link.label, "url": link.url} for link in links],
    }
