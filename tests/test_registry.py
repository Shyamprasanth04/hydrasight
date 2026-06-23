import pytest

from hydrasight.core.registry import ActionRegistry, ActionRegistryError
from hydrasight.models.actions import ActionDefinition, ROECategory


def test_registry_registration():
    registry = ActionRegistry()
    action = ActionDefinition(
        action_id="nmap_scan",
        display_name="Nmap Scan",
        roe_category=ROECategory.RECON,
        description="Run Nmap",
        tool_family="nmap"
    )
    registry.register(action)
    assert registry.get("nmap_scan") == action

def test_registry_aliases():
    registry = ActionRegistry()
    action = ActionDefinition(
        action_id="nmap_scan",
        display_name="Nmap Scan",
        roe_category=ROECategory.RECON,
        description="Run Nmap",
        tool_family="nmap",
        aliases=["scan"]
    )
    registry.register(action)
    assert registry.get("scan") == action
    assert registry.resolve_action_id("scan") == "nmap_scan"

def test_registry_duplicate_action():
    registry = ActionRegistry()
    action = ActionDefinition(
        action_id="nmap_scan",
        display_name="Nmap Scan",
        roe_category=ROECategory.RECON,
        description="Run Nmap",
        tool_family="nmap"
    )
    registry.register(action)
    with pytest.raises(ActionRegistryError):
        registry.register(action)

def test_registry_duplicate_alias():
    registry = ActionRegistry()
    action1 = ActionDefinition(
        action_id="nmap_scan",
        display_name="Nmap Scan",
        roe_category=ROECategory.RECON,
        description="Run Nmap",
        tool_family="nmap",
        aliases=["scan"]
    )
    action2 = ActionDefinition(
        action_id="other_scan",
        display_name="Other Scan",
        roe_category=ROECategory.RECON,
        description="Run Other",
        tool_family="other",
        aliases=["scan"]
    )
    registry.register(action1)
    with pytest.raises(ActionRegistryError):
        registry.register(action2)

def test_registry_missing_action():
    registry = ActionRegistry()
    with pytest.raises(ActionRegistryError):
        registry.get("missing_action")
