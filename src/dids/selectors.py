from src.dids.models import PublishRequest


def get_publish_request_for_update(pr_id: str) -> PublishRequest:
    """
    Loads a publish request by ID with a row-level lock for update
    """
    return PublishRequest.objects.select_for_update().get(pk=pr_id)
