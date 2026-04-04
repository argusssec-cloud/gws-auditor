# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""PydanticAI agents for check quality analysis."""


def __getattr__(name: str):
    if name == "AgentCoordinator":
        from .coordinator import AgentCoordinator
        return AgentCoordinator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["AgentCoordinator"]
