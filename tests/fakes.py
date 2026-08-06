"""In-memory boto3 doubles for the tag-governance handler tests.

These record the write calls the handlers make (tag application, S3 puts, SNS
publishes) and serve deterministic responses for the read calls, so the
handlers can be exercised end-to-end with no network and no real AWS.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


class _ClientError(Exception):
    """Stand-in for botocore ClientError, matched by substring in the handler."""


class _Exceptions:
    ClientError = _ClientError


class FakeS3:
    """Serves bucket tags and records report puts."""

    def __init__(self, bucket_tags: Optional[Dict[str, Dict[str, str]]] = None,
                 raise_no_tag_set: bool = False) -> None:
        self._bucket_tags = bucket_tags or {}
        self._raise_no_tag_set = raise_no_tag_set
        self.exceptions = _Exceptions()
        self.put_calls: List[Dict[str, Any]] = []

    def get_bucket_tagging(self, Bucket: str) -> Dict[str, Any]:
        if self._raise_no_tag_set or Bucket not in self._bucket_tags:
            raise _ClientError("NoSuchTagSet: The TagSet does not exist")
        tags = self._bucket_tags[Bucket]
        return {"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}

    def put_object(self, **kwargs: Any) -> Dict[str, Any]:
        self.put_calls.append(kwargs)
        return {"ETag": "fake-etag"}


class FakeEC2:
    def __init__(self, tags_by_id: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._tags_by_id = tags_by_id or {}

    def describe_tags(self, Filters: List[Dict[str, Any]]) -> Dict[str, Any]:
        resource_ids: List[str] = []
        for f in Filters:
            if f.get("Name") == "resource-id":
                resource_ids.extend(f.get("Values", []))
        tags: List[Dict[str, str]] = []
        for rid in resource_ids:
            for k, v in self._tags_by_id.get(rid, {}).items():
                tags.append({"Key": k, "Value": v})
        return {"Tags": tags}


class FakeRDS:
    def __init__(self, tags_by_arn: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._tags_by_arn = tags_by_arn or {}

    def list_tags_for_resource(self, ResourceName: str) -> Dict[str, Any]:
        tags = self._tags_by_arn.get(ResourceName, {})
        return {"TagList": [{"Key": k, "Value": v} for k, v in tags.items()]}


class FakeDynamoDB:
    def __init__(self, tags_by_arn: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._tags_by_arn = tags_by_arn or {}

    def list_tags_of_resource(self, ResourceArn: str) -> Dict[str, Any]:
        tags = self._tags_by_arn.get(ResourceArn, {})
        return {"Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}


class RecordingTagging:
    """resourcegroupstaggingapi double for the remediator: records tag_resources."""

    def __init__(self, failures: Optional[Dict[str, Any]] = None) -> None:
        self.tag_calls: List[Dict[str, Any]] = []
        self._failures = failures or {}

    def tag_resources(self, ResourceARNList: List[str], Tags: Dict[str, str]) -> Dict[str, Any]:
        self.tag_calls.append({"arns": list(ResourceARNList), "tags": dict(Tags)})
        return {"FailedResourcesMap": dict(self._failures)}


class FakeResourceGroupsTaggingAPI:
    """Drift-reporter double: paginated get_resources over a fixture set.

    ``pages`` maps a resource-type filter to a list of pages, where each page is
    a list of ``{"arn": str, "tags": {k: v}}`` dicts. A page boundary yields a
    PaginationToken so the handler's pagination loop is exercised.
    """

    def __init__(self, pages: Dict[str, List[List[Dict[str, Any]]]]) -> None:
        self._pages = pages

    def get_resources(
        self,
        ResourceTypeFilters: List[str],
        ResourcesPerPage: int = 100,
        PaginationToken: str = "",
    ) -> Dict[str, Any]:
        rtype = ResourceTypeFilters[0]
        pages = self._pages.get(rtype, [[]])
        index = int(PaginationToken) if PaginationToken else 0
        page = pages[index] if index < len(pages) else []
        mappings = [
            {
                "ResourceARN": item["arn"],
                "Tags": [{"Key": k, "Value": v} for k, v in item["tags"].items()],
            }
            for item in page
        ]
        next_token = str(index + 1) if index + 1 < len(pages) else ""
        return {"ResourceTagMappingList": mappings, "PaginationToken": next_token}


class RecordingSNS:
    def __init__(self) -> None:
        self.publish_calls: List[Dict[str, Any]] = []

    def publish(self, **kwargs: Any) -> Dict[str, Any]:
        self.publish_calls.append(kwargs)
        return {"MessageId": "fake-message-id"}


def as_iter(items: Iterable[Any]) -> List[Any]:
    return list(items)
