from blocklist import is_blocked, load_blocklist


def test_load_blocklist_missing_file_returns_empty(tmp_path):
    assert load_blocklist(str(tmp_path / "nope.txt")) == set()


def test_load_blocklist_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "block_email.txt"
    path.write_text("# blocked accounts\n\nbadactor@example.org\n")
    assert load_blocklist(str(path)) == {"badactor@example.org"}


def test_is_blocked_case_insensitive(tmp_path):
    path = tmp_path / "block_email.txt"
    path.write_text("badactor@example.org\n")
    assert is_blocked("BadActor@example.org", str(path)) is True


def test_is_blocked_not_present(tmp_path):
    path = tmp_path / "block_email.txt"
    path.write_text("badactor@example.org\n")
    assert is_blocked("jstudent@example.org", str(path)) is False
