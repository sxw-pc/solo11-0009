import secrets

import pytest

from maskline.pseudomap import PseudoMap, PseudoMapError, PseudonymCollision
from maskline.transformers.pseudonym import pseudonym_token

TEST_KEY = secrets.token_urlsafe(32)

def test_put_get_reveal_and_persistence(tmp_path):
    path = tmp_path / "map.sqlite"
    token = pseudonym_token("张伟", TEST_KEY)
    with PseudoMap(path, create=True) as mapping:
        mapping.put(token, "张伟")
        mapping.put(token, "张伟")
        assert mapping.get(token) == "张伟"
        assert mapping.count() == 1
    with PseudoMap(path) as mapping:
        assert mapping.reveal(token) == "张伟"
        assert mapping.get("missing") is None
        assert list(mapping.iter_entries()) == [(token, "张伟")]

def test_collision_is_rejected(tmp_path):
    token = pseudonym_token("张伟", TEST_KEY)
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        mapping.put(token, "张伟")
        with pytest.raises(PseudonymCollision):
            mapping.put(token, "李娜")

def test_missing_mapping_file_and_token_errors(tmp_path):
    with pytest.raises(PseudoMapError, match="not found"):
        PseudoMap(tmp_path / "missing.sqlite")
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        with pytest.raises(PseudoMapError, match="token not found"):
            mapping.reveal("psn_missing")
