from azure.identity import DefaultAzureCredential


ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def get_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential()
