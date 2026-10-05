from backend.results import KNOWLEDGE, make_finding


def test_every_entry_is_complete_and_usable():
    for key, entry in KNOWLEDGE.items():
        assert entry["severity"] in ("low", "medium", "high"), key
        for field in ("title", "explanation", "fix"):
            assert entry[field].strip(), f"{key} has an empty {field}"
            assert "TODO" not in entry[field], f"{key} still has TODO in {field}"

    finding = make_finding("web.missing_hsts", header="strict-transport-security")
    assert finding["title"] == KNOWLEDGE["web.missing_hsts"]["title"]
    assert finding["severity"] == "medium"
    assert finding["details"] == {"header": "strict-transport-security"}
