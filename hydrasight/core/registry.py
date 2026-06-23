
from hydrasight.models.actions import ActionDefinition


class ActionRegistryError(Exception):
    pass

class ActionRegistry:
    def __init__(self):
        self._actions: dict[str, ActionDefinition] = {}
        self._aliases: dict[str, str] = {}

    def register(self, action: ActionDefinition) -> None:
        if action.action_id in self._actions:
            raise ActionRegistryError(f"Action '{action.action_id}' already registered.")
        self._actions[action.action_id] = action

        for alias in action.aliases:
            if alias in self._aliases:
                raise ActionRegistryError(f"Alias '{alias}' already registered to '{self._aliases[alias]}'.")
            self._aliases[alias] = action.action_id

    def get(self, action_id_or_alias: str) -> ActionDefinition:
        action_id = self._aliases.get(action_id_or_alias, action_id_or_alias)
        if action_id not in self._actions:
            raise ActionRegistryError(f"Action '{action_id_or_alias}' not found in registry.")
        return self._actions[action_id]

    def resolve_action_id(self, action_id_or_alias: str) -> str | None:
        action_id = self._aliases.get(action_id_or_alias, action_id_or_alias)
        if action_id in self._actions:
            return action_id
        return None

    def list_actions(self) -> list[ActionDefinition]:
        return list(self._actions.values())

    def clear(self) -> None:
        self._actions.clear()
        self._aliases.clear()

# Global registry instance
registry = ActionRegistry()
