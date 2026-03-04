"""Tests for ctf_forensics.py — pure-Python helper functions only (no external CLI tools)."""

import math
import os
import sys
import tempfile

import pytest

# Allow imports from the tools directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ctf_forensics import (
    _calculate_entropy,
    _check_trailing_data,
    _entropy_interpretation,
)

# ── _calculate_entropy tests ─────────────────────────────────────────────────


class TestCalculateEntropy:
    def test_empty_data(self):
        assert _calculate_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All zeros — only one symbol, entropy = 0
        data = b"\x00" * 1000
        assert _calculate_entropy(data) == 0.0

    def test_two_equal_symbols(self):
        # Half 0x00, half 0x01 — entropy should be 1.0 bit
        data = b"\x00" * 500 + b"\x01" * 500
        entropy = _calculate_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_four_equal_symbols(self):
        # Four equally distributed symbols — entropy should be 2.0 bits
        data = b"\x00" * 250 + b"\x01" * 250 + b"\x02" * 250 + b"\x03" * 250
        entropy = _calculate_entropy(data)
        assert abs(entropy - 2.0) < 0.01

    def test_all_256_bytes_uniform(self):
        # All 256 byte values equally distributed — max entropy = 8.0
        data = bytes(range(256)) * 100
        entropy = _calculate_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_highly_random_data(self):
        # os.urandom should produce high entropy (close to 8)
        data = os.urandom(10000)
        entropy = _calculate_entropy(data)
        assert entropy > 7.5

    def test_english_text_moderate_entropy(self):
        # ASCII English text typically has entropy around 3.5-5.0
        text = (
            b"The quick brown fox jumps over the lazy dog. "
            b"This sentence contains a reasonable distribution "
            b"of English letters and should have moderate entropy."
        )
        entropy = _calculate_entropy(text)
        assert 3.0 < entropy < 5.5

    def test_single_byte_data(self):
        data = b"\x42"
        assert _calculate_entropy(data) == 0.0

    def test_entropy_is_non_negative(self):
        for data in [b"", b"\x00", b"abc", os.urandom(100)]:
            assert _calculate_entropy(data) >= 0.0

    def test_entropy_at_most_eight(self):
        # Shannon entropy of byte data is at most 8 bits
        data = os.urandom(10000)
        assert _calculate_entropy(data) <= 8.0


# ── _entropy_interpretation tests ────────────────────────────────────────────


class TestEntropyInterpretation:
    def test_very_low(self):
        result = _entropy_interpretation(0.5)
        assert "low" in result.lower() or "empty" in result.lower()

    def test_low(self):
        result = _entropy_interpretation(2.0)
        assert "low" in result.lower() or "plaintext" in result.lower()

    def test_medium(self):
        result = _entropy_interpretation(4.0)
        assert "medium" in result.lower() or "structured" in result.lower()

    def test_high(self):
        result = _entropy_interpretation(6.0)
        assert "high" in result.lower() or "compressed" in result.lower()

    def test_very_high(self):
        result = _entropy_interpretation(7.5)
        assert "high" in result.lower() or "encrypted" in result.lower()

    def test_near_maximum(self):
        result = _entropy_interpretation(7.95)
        assert (
            "maximum" in result.lower()
            or "encrypted" in result.lower()
            or "random" in result.lower()
        )

    def test_boundary_values(self):
        # Each threshold boundary should return a valid string
        for val in [0.0, 0.99, 1.0, 3.49, 3.5, 4.99, 5.0, 6.99, 7.0, 7.89, 7.9, 8.0]:
            result = _entropy_interpretation(val)
            assert isinstance(result, str)
            assert len(result) > 0


# ── _check_trailing_data tests ───────────────────────────────────────────────


class TestCheckTrailingData:
    def test_non_matching_mime_returns_not_found(self):
        # Create a simple temp file and check with a non-image mime type
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"just some data")
            path = f.name
        try:
            result = _check_trailing_data(path, "application/octet-stream")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_png_without_iend_returns_not_found(self):
        # A file that claims to be PNG but has no IEND marker
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_png_with_trailing_data(self):
        # Simulate a PNG with IEND chunk followed by trailing data.
        # The function searches for b"IEND" and skips 12 bytes from that position
        # (covering IEND tag + CRC + padding). We place the trailing data so it
        # starts well past that 12-byte window.
        #
        # Build file: [PNG header][padding][IEND text][8 bytes post-IEND][trailing]
        # The function finds "IEND" at some offset, then end_pos = offset + 12.
        png_header = b"\x89PNG\r\n\x1a\n"
        body_padding = b"\x00" * 50
        # Just the IEND marker followed by 8 bytes of "CRC + extra"
        iend_and_crc = b"IEND" + b"\xae\x42\x60\x82" + b"\x00\x00\x00\x00"
        trailing = b"SECRET_FLAG_HERE"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(png_header + body_padding + iend_and_crc + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is True
            assert result["size"] == len(trailing)
            assert "SECRET_FLAG_HERE" in result["preview"]
        finally:
            os.unlink(path)

    def test_png_without_trailing_data(self):
        # PNG ending exactly at the point the function considers "end of IEND".
        # The function does end_pos = iend_pos + 12, so we need exactly 12 bytes
        # from the "IEND" string to EOF (IEND(4) + CRC(4) + 4 extra bytes).
        png_header = b"\x89PNG\r\n\x1a\n"
        body_padding = b"\x00" * 50
        iend_and_crc = b"IEND" + b"\xae\x42\x60\x82" + b"\x00\x00\x00\x00"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(png_header + body_padding + iend_and_crc)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_jpeg_with_trailing_data(self):
        # Simulate JPEG ending with EOI marker (FF D9) + trailing data
        trailing = b"HIDDEN_DATA"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9" + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/jpeg")
            assert result["found"] is True
            assert result["size"] == len(trailing)
            assert "HIDDEN_DATA" in result["preview"]
        finally:
            os.unlink(path)

    def test_jpeg_without_trailing_data(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")
            path = f.name
        try:
            result = _check_trailing_data(path, "image/jpeg")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_zip_with_trailing_data(self):
        # Simulate ZIP EOCD record followed by trailing data
        eocd = b"\x50\x4b\x05\x06" + b"\x00" * 18  # minimum EOCD = 22 bytes total
        trailing = b"EXTRA"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
            f.write(b"\x50\x4b\x03\x04" + b"\x00" * 50 + eocd + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "application/zip")
            assert result["found"] is True
            assert result["size"] == len(trailing)
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_not_found(self):
        # Should handle gracefully (exception caught internally)
        result = _check_trailing_data("/tmp/nonexistent_file_xyz.bin", "image/png")
        assert result["found"] is False
