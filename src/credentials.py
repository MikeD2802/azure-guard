from __future__ import annotations

from src.scopes import ARM_SCOPE, GRAPH_SCOPE

__all__ = ["ARM_SCOPE", "GRAPH_SCOPE", "get_credential"]


def get_credential():
    """Build the ambient Azure credential.

    Imported lazily so that modules which only need the scope constants do not
    drag in the Azure SDK.
    """
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential()
