"""Antivirus scanning of uploads via clamd (ASVS 5.0.0-5.4.3).

Image re-encoding in ``uploads.py`` already destroys polyglot payloads for
photos, but a PDF or a text file is stored byte for byte - re-encoding is not
a substitute for scanning, and there was previously no scanner at all. This
module speaks clamd's own wire protocol (``INSTREAM``) directly rather than
pulling in a client library: it is four moving parts - connect, send a
length-prefixed stream, read one line back - and a dependency earns its
place less than four functions do.

**Fail closed is the whole point.** A scanner that is unreachable, times out,
or answers with something this client does not recognise is treated exactly
like a positive match by the caller: the upload is refused. Silently treating
"I could not ask" as "the answer was no" would make the scanner optional in
exactly the circumstances - clamd down, overloaded, mid-restart - where an
attacker benefits most from it being skipped.
"""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

#: clamd's INSTREAM command wants the payload chunked. One chunk is enough
#: for anything under UPLOAD_MAX_BYTES, but the protocol is a length-prefixed
#: stream either way, so chunking costs nothing extra to do properly.
_CHUNK_BYTES = 1024 * 1024


class ScanUnavailable(RuntimeError):
    """clamd could not be reached, timed out, or answered unintelligibly.

    Callers must fail closed on this - reject the upload - the same as on a
    positive match. See the module docstring.
    """


class ScanPositive(RuntimeError):
    """clamd identified the stream as malicious.

    ``signature`` is clamd's name for what it matched (e.g.
    ``Win.Test.EICAR_HDB-1``), kept for the audit log. It is not shown to the
    uploader - see ``uploads.py`` for the user-facing message.
    """

    def __init__(self, signature: str) -> None:
        self.signature = signature
        super().__init__(signature)


def scan(data: bytes, *, host: str, port: int, timeout: float) -> None:
    """Submit ``data`` to clamd's ``INSTREAM`` command.

    Returns normally on a clean result. Raises :class:`ScanPositive` on a
    match and :class:`ScanUnavailable` for anything else - connection
    failure, timeout, or a response this client does not recognise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), _CHUNK_BYTES):
                chunk = data[offset : offset + _CHUNK_BYTES]
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
            sock.sendall((0).to_bytes(4, "big"))  # zero-length chunk ends the stream
            raw = _read_response(sock)
    except OSError as exc:
        raise ScanUnavailable(f"clamd at {host}:{port} unreachable: {exc}") from exc

    text = raw.decode("utf-8", "replace").strip("\0").strip()

    if text.endswith("OK"):
        return

    if text.endswith("FOUND"):
        # "stream: <signature> FOUND"
        signature = text.rsplit(" ", 2)[-2] if text.count(" ") >= 2 else text
        logger.warning(
            "upload_scan_positive", extra={"extra_fields": {"result": text}}
        )
        raise ScanPositive(signature)

    # ERROR responses, a truncated reply, a protocol clamd doesn't speak the
    # way this client expects - none of these are "clean". Fail closed.
    raise ScanUnavailable(
        f"clamd at {host}:{port} returned an unrecognised response: {text!r}"
    )


def _read_response(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        piece = sock.recv(4096)
        if not piece:
            break
        chunks.append(piece)
    return b"".join(chunks)
