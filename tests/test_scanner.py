# run with: python -m pytest tests/
import pytest
import os
from unicode_canary.scanner import scan_file, scan_content

def test_clean_file_has_no_findings():
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    findings, error = scan_file(os.path.join(samples_dir, "clean_file.py"))
    assert error is None, f"Unexpected error: {error}"
    assert len(findings) == 0, f"Expected 0 findings, got {len(findings)}: {findings}"

def test_infected_file_has_findings():
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    findings, error = scan_file(os.path.join(samples_dir, "infected_file.py"))
    assert error is None
    assert len(findings) > 0, "Expected to find threats but found none!"

def test_detects_bidi_override():
    content = "access = \u202E'admin'"  
    findings = scan_content(content, "test.py")
    bidi = [f for f in findings if f.category == "bidi"]
    assert len(bidi) >= 1
    assert bidi[0].char_unicode == "U+202E"
    assert bidi[0].risk_level == "CRITICAL"

def test_detects_zero_width():
    content = "secret = '\u200B\u200C'"  
    findings = scan_content(content, "test.js")
    zw = [f for f in findings if f.category == "zero_width"]
    assert len(zw) == 2  

def test_detects_homoglyph():
    content = "def v\u0430lidate(x): pass"  
    findings = scan_content(content, "test.py")
    homoglyphs = [f for f in findings if f.category == "homoglyph"]
    assert len(homoglyphs) >= 1
    assert homoglyphs[0].char_unicode == "U+0430"

def test_detects_tag_characters():
    content = "# Normal comment \U000E0041\U000E0042"
    findings = scan_content(content, "test.py")
    tags = [f for f in findings if f.category == "tag"]
    assert len(tags) == 2

def test_correct_line_numbers():
    content = "line_one = 'clean'\nline_two = '\u202E'"
    findings = scan_content(content, "test.py")
    assert findings[0].line_number == 2

def test_correct_column_numbers():
    content = "x = '\u202E'"
    findings = scan_content(content, "test.py")
    assert findings[0].column == 6