"""Upload validation: content sniffing, re-encoding, metadata stripping."""

from __future__ import annotations

import io

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from doom.security.uploads import UploadRejected, store_upload


def _jpeg_bytes(size=(400, 300)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, (120, 80, 40)).save(buffer, format="JPEG")
    return buffer.getvalue()


def _storage(data: bytes, filename: str, content_type: str) -> FileStorage:
    return FileStorage(
        stream=io.BytesIO(data), filename=filename, content_type=content_type
    )


class TestContentSniffing:
    def test_text_renamed_as_jpeg_is_rejected(self, tmp_path):
        """The filename and the declared type are both attacker-controlled.

        Only the bytes are trustworthy, which is what libmagic reads.
        """
        storage = _storage(b"#!/bin/sh\necho hello\n", "photo.jpg", "image/jpeg")
        with pytest.raises(UploadRejected):
            store_upload(storage, str(tmp_path))

    def test_svg_is_rejected(self, tmp_path):
        """SVG is a document format that can carry <script>.

        Served same-origin, it is stored XSS. Excluded by allowlist rather
        than by trying to sanitise it.
        """
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        with pytest.raises(UploadRejected):
            store_upload(_storage(svg, "logo.svg", "image/svg+xml"), str(tmp_path))

    def test_zip_is_rejected(self, tmp_path):
        # Archives invite zip-slip and nothing here needs them.
        zip_bytes = b"PK\x03\x04" + b"\x00" * 64
        with pytest.raises(UploadRejected):
            store_upload(_storage(zip_bytes, "a.zip", "application/zip"), str(tmp_path))

    def test_empty_file_is_rejected(self, tmp_path):
        with pytest.raises(UploadRejected):
            store_upload(_storage(b"", "empty.jpg", "image/jpeg"), str(tmp_path))


class TestReEncoding:
    def test_valid_jpeg_is_accepted(self, tmp_path):
        result = store_upload(_storage(_jpeg_bytes(), "ok.jpg", "image/jpeg"), str(tmp_path))
        assert result.kind == "photo"
        assert result.content_type == "image/jpeg"

    def test_appended_payload_does_not_survive(self, tmp_path):
        """The re-encode is the control, not the resize.

        Output is written from decoded pixels into a new container, so a
        polyglot's trailing payload is not carried across.
        """
        poisoned = _jpeg_bytes() + b"<script>alert('xss')</script>"
        result = store_upload(_storage(poisoned, "p.jpg", "image/jpeg"), str(tmp_path))

        stored = (tmp_path / result.stored_name).read_bytes()
        assert b"<script>" not in stored
        assert b"alert" not in stored

    def test_exif_is_stripped(self, tmp_path):
        """EXIF is where photographs keep GPS coordinates.

        A picture of a shelf would otherwise publish the address of the
        building it is in (T-22).
        """
        buffer = io.BytesIO()
        image = Image.new("RGB", (300, 200), (10, 20, 30))
        exif = image.getexif()
        exif[271] = "SecretCameraMake"
        image.save(buffer, format="JPEG", exif=exif)

        result = store_upload(
            _storage(buffer.getvalue(), "gps.jpg", "image/jpeg"), str(tmp_path)
        )
        stored = (tmp_path / result.stored_name).read_bytes()
        assert b"SecretCameraMake" not in stored

    def test_thumbnail_is_generated(self, tmp_path):
        result = store_upload(
            _storage(_jpeg_bytes((2000, 1500)), "big.jpg", "image/jpeg"), str(tmp_path)
        )
        assert result.thumbnail_name
        assert (tmp_path / result.thumbnail_name).exists()


class TestAntivirusScanning:
    """clamd scans raw bytes before decode (ASVS 5.0.0-5.4.3).

    These run against the real clamd the `test` compose service depends on
    (health-gated - see docker-compose.yml) rather than a mock, matching how
    the rest of this suite runs against real PostgreSQL instead of SQLite.
    """

    # The standard EICAR test string: harmless bytes every AV engine is
    # built to flag on sight, used to test detection without a real sample.
    _EICAR = (
        rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    def test_clean_file_is_accepted(self, tmp_path):
        result = store_upload(
            _storage(b"nothing malicious here, just notes", "notes.txt", "text/plain"),
            str(tmp_path),
        )
        assert result.kind == "document"

    def test_eicar_test_file_is_rejected(self, tmp_path):
        with pytest.raises(UploadRejected):
            store_upload(
                _storage(self._EICAR, "notes.txt", "text/plain"), str(tmp_path)
            )

    def test_image_uploads_are_scanned_too(self, tmp_path, monkeypatch):
        """The scan gate applies to every accepted type, not just documents.

        Monkeypatches the scanner rather than embedding EICAR in a JPEG and
        asking clamd to find it: EICAR's signature is a file-start match, and
        does not reliably fire on a string appended after real image bytes -
        that is a property of the test string, not of this pipeline. What
        needs proving is that ``store_upload`` does not skip the scan for
        ``is_image`` content before Pillow ever sees it, which this does
        directly.
        """
        from doom.security import av

        def _positive(data, **kwargs):
            raise av.ScanPositive("Test-Signature")

        monkeypatch.setattr(av, "scan", _positive)
        with pytest.raises(UploadRejected):
            store_upload(_storage(_jpeg_bytes(), "p.jpg", "image/jpeg"), str(tmp_path))

    def test_unreachable_scanner_fails_closed(self, tmp_path):
        """No scanner answering must refuse the upload, not silently allow it."""
        with pytest.raises(UploadRejected):
            store_upload(
                _storage(b"harmless content", "notes.txt", "text/plain"),
                str(tmp_path),
                clamd_host="127.0.0.1",
                clamd_port=1,
                clamd_timeout=2,
            )


class TestStoredNames:
    def test_stored_name_is_generated_not_derived(self, tmp_path):
        """No user-controlled string reaches the filesystem.

        This is what makes traversal impossible by construction rather than by
        filtering "../" out of something (T-11).
        """
        result = store_upload(
            _storage(_jpeg_bytes(), "../../etc/passwd.jpg", "image/jpeg"), str(tmp_path)
        )
        assert "/" not in result.stored_name
        assert ".." not in result.stored_name
        assert "passwd" not in result.stored_name
        assert (tmp_path / result.stored_name).exists()

    def test_original_name_is_kept_for_display_only(self, tmp_path):
        result = store_upload(
            _storage(_jpeg_bytes(), "holiday photo.jpg", "image/jpeg"), str(tmp_path)
        )
        assert result.original_name == "holiday photo.jpg"
        assert result.original_name != result.stored_name

    def test_control_characters_stripped_from_display_name(self, tmp_path):
        # A newline in a filename is a log-forging primitive (T-17).
        result = store_upload(
            _storage(_jpeg_bytes(), "evil\nname\r.jpg", "image/jpeg"), str(tmp_path)
        )
        assert "\n" not in result.original_name
        assert "\r" not in result.original_name
