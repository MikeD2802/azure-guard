"""OAuth scopes for the APIs this tool reads.

Kept free of any Azure SDK import so that collection, diffing and
classification logic stays importable (and unit-testable) without
credentials or the SDK installed.
"""

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
