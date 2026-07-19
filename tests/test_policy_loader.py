from __future__ import annotations

from pathlib import Path

import pytest

from qarai_agent_guard.core.loaders.policy_loader import PolicyLoader, PolicyLoaderError
from qarai_agent_guard.core.schemas.events import Action


def test_load_default_policy_yaml():
    loader = PolicyLoader()
    policy = loader.load_default()
    assert policy.name == "default"


def test_load_custom_policy(tmp_path: Path):
    policy_file = tmp_path / "custom.yaml"
    policy_file.write_text(
        """
version: "1.0"
name: custom
default_action: allow
rules:
  - severities: [critical]
    action: quarantine
  - severities: [high, medium]
    action: warn
""".strip(),
        encoding="utf-8",
    )
    policy = PolicyLoader().load(policy_file)
    assert policy.name == "custom"
    assert policy.default_action == Action.ALLOW


def test_invalid_policy_raises(tmp_path: Path):
    policy_file = tmp_path / "broken.yaml"
    policy_file.write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(PolicyLoaderError):
        PolicyLoader().load(policy_file)
