import socket

from adsink import __main__ as app


def test_fails_cleanly_when_blocklist_is_missing(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(app, "BLOCKLIST_FILE", tmp_path / "missing.txt")

    assert app.main() == 1
    assert "Cannot read blocklist" in caplog.text


def test_fails_cleanly_when_port_is_taken(tmp_path, monkeypatch, caplog):
    blocklist_file = tmp_path / "blocklist.txt"
    blocklist_file.write_text("doubleclick.net\n", encoding="utf-8")
    monkeypatch.setattr(app, "BLOCKLIST_FILE", blocklist_file)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
        taken.bind((app.HOST, 0))
        monkeypatch.setattr(app, "PORT", taken.getsockname()[1])

        assert app.main() == 1

    assert "Cannot listen on" in caplog.text