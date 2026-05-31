from sentinel.config import Settings
from sentinel.discord_interactions import extract_query, interaction_message, is_security_team_member


def test_extract_query_from_slash_options():
    assert extract_query({"data": {"options": [{"name": "query", "value": "are we safe to release?"}]}}) == "are we safe to release?"


def test_discord_role_gate_uses_configured_role_id(tmp_path):
    settings = Settings.from_env().__class__(**{**Settings.from_env().__dict__, "home": tmp_path, "discord_security_role_id": "role-1"})
    assert is_security_team_member({"member": {"roles": ["role-1"]}}, settings)
    assert not is_security_team_member({"member": {"roles": ["role-2"]}}, settings)


def test_interaction_message_is_ephemeral():
    message = interaction_message("hello")
    assert message["data"]["flags"] == 64
