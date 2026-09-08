"""Upload handling.

The pipeline, in order, and every step is load-bearing:

    size cap -> magic-byte sniff -> allowlist -> decode -> re-encode -> store

**Nothing the client says about the file is believed.**  The filename, the
extension and the Content-Type header are all attacker-controlled strings.
The only trustworthy statement about an uploaded file is what its bytes
actually are, which is what ``python-magic`` reads.

**Images are decoded and re-encoded rather than stored as received.**  This is
the step that does the most work.  It destroys polyglot files - a valid GIF
that is also valid PHP, or a JPEG carrying an HTML payload in a comment
segment - because the output is generated from decoded pixels and contains
nothing of the original container.  It also strips EXIF, and EXIF is where
photographs keep GPS coordinates: a picture of a shelf can otherwise publish
the address of the building it is in (T-22).

**Stored names are generated, never derived.**  ``original_name`` is kept in
the database for display and is never joined to a path.  No user-controlled
string reaches the filesystem at any point, which is what makes traversal
impossible by construction rather than by trying to filter ``../`` out of
something (T-11).
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import uuid
from dataclasses import dataclass

import magic
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.datastructures import FileStorage

from .. import validation as v

logger = logging.getLogger(__name__)

# A decompression bomb is a few kilobytes that expands into gigabytes of
# pixels. Pillow refuses anything larger than this rather than exhausting the
# container's memory (T-29).
Image.MAX_IMAGE_PIXELS = v.MAX_IMAGE_PIXELS

#: Bytes to read for content sniffing. libmagic needs far fewer, but this
#: covers formats that carry their signature slightly later.
_SNIFF_BYTES = 4096


class UploadRejected(ValueError):
    """Raised when a file fails validation. The message is user-facing."""


@dataclass(frozen=True)
class StoredFile:
    stored_name: str
    thumbnail_name: str | None
    original_name: str
    content_type: str
    byte_size: int
    sha256: str
    kind: str


def _safe_original_name(raw: str | None) -> str:
    """Keep a display-only version of the client's filename.

    Never used to build a path. Control characters and separators are stripped
    anyway, because this string is rendered in HTML and written to logs, and a
    newline in a filename is a log-forging primitive (T-17).
    """
    name = (raw or "file").strip()
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '\r\n\t"<>')
    return name[:255] or "file"


def _sniff(data: bytes) -> str:
    """Identify content by its bytes."""
    try:
        return magic.from_buffer(data, mime=True) or "application/octet-stream"
    except Exception:
        logger.exception("magic_sniff_failed")
        return "application/octet-stream"


def _read_bounded(storage: FileStorage) -> bytes:
    """Read the upload, refusing anything over the cap.

    Flask's MAX_CONTENT_LENGTH already rejects oversized requests before this
    point, and Caddy rejects larger ones still. This is the third gate, and it
    exists because the first two protect the *request* while this one protects
    the *file* - a multipart body can carry several parts under one limit.
    """
    storage.stream.seek(0, os.SEEK_END)
    size = storage.stream.tell()
    storage.stream.seek(0)

    if size == 0:
        raise UploadRejected("That file is empty.")

    if size > v.UPLOAD_MAX_BYTES:
        limit_mb = v.UPLOAD_MAX_BYTES // (1024 * 1024)
        raise UploadRejected(f"Files must be {limit_mb} MB or smaller.")

    return storage.stream.read(v.UPLOAD_MAX_BYTES + 1)[: v.UPLOAD_MAX_BYTES]


def _process_image(data: bytes, content_type: str) -> tuple[bytes, bytes, str, str]:
    """Decode and re-encode an image, returning (full, thumbnail, mime, ext).

    The re-encode is the security step, not the resize. Output pixels are
    written into a brand-new container, so anything that rode along in the
    original file - trailing archives, script tags in metadata, a second
    format's header - is simply not carried across.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()  # structural check before trusting the decoder
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise UploadRejected("That image could not be read.") from exc

    try:
        with Image.open(io.BytesIO(data)) as img:
            # Honour the EXIF orientation flag, then discard EXIF entirely.
            # Without this the picture would appear rotated once the metadata
            # that described the rotation is gone.
            img = ImageOps.exif_transpose(img)

            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")

            img.thumbnail(
                (v.IMAGE_MAX_DIMENSION, v.IMAGE_MAX_DIMENSION), Image.LANCZOS
            )

            full = io.BytesIO()
            # A fresh Image object is saved; no original bytes survive.
            img.save(full, format="JPEG", quality=v.IMAGE_JPEG_QUALITY, optimize=True)

            img.thumbnail(
                (v.THUMBNAIL_MAX_DIMENSION, v.THUMBNAIL_MAX_DIMENSION), Image.LANCZOS
            )
            thumb = io.BytesIO()
            img.save(thumb, format="JPEG", quality=80, optimize=True)

    except Image.DecompressionBombError as exc:
        raise UploadRejected("That image is too large to process.") from exc
    except (OSError, ValueError) as exc:
        raise UploadRejected("That image could not be processed.") from exc

    return full.getvalue(), thumb.getvalue(), "image/jpeg", ".jpg"


def check_quota(owner_id, incoming_bytes: int) -> None:
    """Refuse an upload that would exceed the account's storage ceiling.

    Checked BEFORE anything is written, so a refused upload costs no disk at
    all (T-46). Unbounded uploads are a disk-exhaustion path, and an
    availability failure is still a security failure however well-formed each
    individual file was.
    """
    from sqlalchemy import func, select

    from ..extensions import db
    from ..models import Attachment

    used = db.session.scalar(
        select(func.coalesce(func.sum(Attachment.byte_size), 0))
        .where(Attachment.owner_id == owner_id)
    ) or 0

    if used + incoming_bytes > v.STORAGE_QUOTA_BYTES:
        used_mb = used // (1024 * 1024)
        quota_mb = v.STORAGE_QUOTA_BYTES // (1024 * 1024)
        raise UploadRejected(
            f"That would exceed your {quota_mb} MB storage limit "
            f"({used_mb} MB used). Delete something first."
        )


def _existing_blob(owner_id, digest: str):
    """Find an identical file this owner has already stored.

    Deduplication is scoped **per owner, never globally**. Sharing a blob
    between accounts would leak the fact that two people hold an identical
    file, and would make deletion behaviour an oracle for it: whether the bytes
    survive your delete tells you whether someone else has the same picture
    (T-47). Per-owner dedup costs a little disk and closes that entirely.
    """
    from sqlalchemy import select

    from ..extensions import db
    from ..models import Attachment

    return db.session.execute(
        select(Attachment).where(
            Attachment.owner_id == owner_id, Attachment.sha256 == digest
        ).limit(1)
    ).scalar_one_or_none()


def store_upload(storage: FileStorage, upload_dir: str, *, owner_id=None) -> StoredFile:
    """Validate and persist one uploaded file."""
    if storage is None or not storage.filename:
        raise UploadRejected("No file was selected.")

    original_name = _safe_original_name(storage.filename)
    data = _read_bounded(storage)

    # Determined from content. The extension and the browser's Content-Type
    # are ignored entirely: renaming evil.txt to photo.jpg changes nothing.
    content_type = _sniff(data[:_SNIFF_BYTES])

    if content_type not in v.ALLOWED_UPLOAD_TYPES:
        # SVG lands here, deliberately. It is a document format that can carry
        # <script>, so serving one same-origin is stored XSS. Archives land
        # here too (zip-slip). An allowlist means neither had to be predicted.
        raise UploadRejected(
            f"{original_name} is a {content_type} file, which is not accepted. "
            f"Photos may be JPEG, PNG or WebP; documents may be PDF, "
            f"plain text or Markdown."
        )

    is_image = content_type in v.ALLOWED_IMAGE_TYPES
    thumbnail_name: str | None = None

    if is_image:
        payload, thumb_payload, content_type, extension = _process_image(
            data, content_type
        )
        kind = "photo"
    else:
        payload = data
        thumb_payload = None
        extension = v.ALLOWED_DOC_TYPES[content_type]
        kind = "document"

    digest = hashlib.sha256(payload).hexdigest()

    if owner_id is not None:
        # Reuse an identical blob this owner already has. The sha256 was
        # always being computed and then ignored; this is what it was for.
        duplicate = _existing_blob(owner_id, digest)
        if duplicate is not None:
            logger.info(
                "upload_deduplicated",
                extra={"extra_fields": {"sha256": digest[:16]}},
            )
            return StoredFile(
                stored_name=duplicate.stored_name,
                thumbnail_name=duplicate.thumbnail_name,
                original_name=original_name,
                content_type=duplicate.content_type,
                byte_size=duplicate.byte_size,
                sha256=digest,
                kind=duplicate.kind,
            )

        check_quota(owner_id, len(payload) + len(thumb_payload or b""))

    # The only name that ever touches the filesystem, and we generated it.
    stored_name = f"{uuid.uuid4().hex}{extension}"

    os.makedirs(upload_dir, exist_ok=True)
    _write_file(os.path.join(upload_dir, stored_name), payload)

    if thumb_payload is not None:
        thumbnail_name = f"{uuid.uuid4().hex}.jpg"
        _write_file(os.path.join(upload_dir, thumbnail_name), thumb_payload)

    logger.info(
        "upload_stored",
        extra={"extra_fields": {
            "kind": kind,
            "content_type": content_type,
            "bytes": len(payload),
            "sha256": digest[:16],
        }},
    )

    return StoredFile(
        stored_name=stored_name,
        thumbnail_name=thumbnail_name,
        original_name=original_name,
        content_type=content_type,
        byte_size=len(payload),
        sha256=digest,
        kind=kind,
    )


def _write_file(path: str, payload: bytes) -> None:
    """Write with owner-only permissions.

    0600 rather than the default: nothing else in the container has any
    business reading user uploads, and a narrow mode costs nothing.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def resolve_stored_path(upload_dir: str, stored_name: str) -> str:
    """Resolve a stored filename to an absolute path, refusing escapes.

    ``stored_name`` comes from our own database and is always a generated
    UUID, so this cannot currently fail. It is checked anyway: the guarantee
    depends on an invariant elsewhere in the code, and a defence that costs
    two lines should not depend on a future maintainer preserving it.
    """
    base = os.path.realpath(upload_dir)
    candidate = os.path.realpath(os.path.join(base, stored_name))

    if not candidate.startswith(base + os.sep):
        logger.error(
            "path_traversal_attempt_blocked",
            extra={"extra_fields": {"stored_name": stored_name[:80]}},
        )
        raise UploadRejected("That file could not be located.")

    return candidate


def delete_stored(upload_dir: str, *names: str | None, still_referenced=None) -> None:
    """Unlink stored blobs that nothing else points at.

    With deduplication, one file on disk can back several attachment rows, so
    deleting a row must not delete the bytes another row is still using.
    ``still_referenced`` is a callable returning True when a name is in use.
    """
    for name in names:
        if not name:
            continue
        if still_referenced is not None and still_referenced(name):
            logger.info(
                "upload_blob_retained",
                extra={"extra_fields": {"reason": "still referenced"}},
            )
            continue
        try:
            os.unlink(resolve_stored_path(upload_dir, name))
        except (OSError, UploadRejected):
            logger.warning("upload_delete_failed", extra={"extra_fields": {"name": name}})


def storage_used(owner_id) -> int:
    from sqlalchemy import func, select

    from ..extensions import db
    from ..models import Attachment

    return db.session.scalar(
        select(func.coalesce(func.sum(Attachment.byte_size), 0))
        .where(Attachment.owner_id == owner_id)
    ) or 0
