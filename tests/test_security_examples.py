from pathlib import Path
import pytest
from lab.security_examples import *

def test_path_traversal(tmp_path):
    assert ".." in str(vulnerable_path(tmp_path, "../outside.txt"))
    with pytest.raises(UnsafeInput): safe_path(tmp_path, "../outside.txt")
    assert safe_path(tmp_path, "docs/a.txt").is_relative_to(tmp_path)

def test_zip_slip_targets(tmp_path):
    assert vulnerable_zip_target(tmp_path, "../../escape").resolve() != tmp_path / "escape"
    with pytest.raises(UnsafeInput): safe_zip_target(tmp_path, "../../escape")
    with pytest.raises(UnsafeInput): safe_zip_target(tmp_path, "C:\\escape")

def test_subprocess_arguments_are_not_shell_text():
    value = "report; synthetic-command"
    assert ";" in vulnerable_command("scanner", value)
    assert safe_command("scanner", value) == ["scanner", "--input", value]

def test_ssrf_url_policy_without_network():
    url = "https://example.invalid/resource"
    assert vulnerable_url_allowed("http://127.0.0.1/admin")
    assert not safe_url_allowed(url, ["127.0.0.1"])
    assert not safe_url_allowed("https://user:pass@example.invalid/", ["192.0.2.1"])
    assert safe_url_allowed(url, ["93.184.216.34"])

def test_token_comparison_contract():
    assert vulnerable_token_equal(b"token", b"token")
    assert safe_token_equal(b"token", b"token")
    assert not safe_token_equal(b"token", b"other")

def test_upload_signature_and_size():
    assert vulnerable_upload_allowed("payload.png", b"not an image")
    assert not safe_upload_allowed("payload.png", b"not an image")
    assert safe_upload_allowed("image.png", PNG + b"synthetic")
    assert not safe_upload_allowed("../image.png", PNG)
    assert not safe_upload_allowed("image.png", PNG + b"x" * 20, max_bytes=10)
