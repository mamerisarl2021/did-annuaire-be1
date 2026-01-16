from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from math import ceil
from typing import Any

from django.db.models import QuerySet


def _get_int(source: dict[str, Any], key: str, default: int) -> int:
    raw = source.get(key)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(1, value)


def _count(data: Any) -> int:
    if isinstance(data, QuerySet):
        return data.count()
    try:
        return len(data)  # list/tuple
    except TypeError:
        return 0


def _with_query(request, **updates) -> str:
    """
    Build an absolute URL with updated query params (preserve others).
    """
    url = request.build_absolute_uri()
    scheme, netloc, path, query, frag = urlsplit(url)
    q = dict(parse_qsl(query, keep_blank_values=True))
    for k, v in updates.items():
        if v is None:
            q.pop(k, None)
        else:
            q[k] = str(v)
    return urlunsplit((scheme, netloc, path, urlencode(q), frag))


class Paginator:
    """
    Simple page-based paginator for Django/Ninja controllers.

    Usage in a controller:
        paginator = Paginator(default_page_size=20, max_page_size=100)
        items, meta = paginator.paginate_queryset(qs, request)
        # serialize items as needed, then:
        return self.create_response(
            message="OK",
            data={"items": serialized, "pagination": meta},
            status_code=200,
        )
    """

    def __init__(self, *, page_param: str = "page", page_size_param: str = "page_size", default_page_size: int = 20,
                 max_page_size: int = 100,):
        self.page_param = page_param
        self.page_size_param = page_size_param
        self.default_page_size = default_page_size
        self.max_page_size = max_page_size

    def _page_and_size(self, request) -> tuple[int, int]:
        params = request.GET
        page = _get_int(params, self.page_param, 1)
        size = _get_int(params, self.page_size_param, self.default_page_size)
        size = min(self.max_page_size, size)
        return page, size

    def paginate_queryset(self, data: Any, request) -> tuple[list[Any], dict[str, Any]]:
        page, size = self._page_and_size(request)
        total = _count(data)

        start = (page - 1) * size
        end = start + size

        if isinstance(data, QuerySet):
            page_items = list(data[start:end])
        else:
            page_items = list(data)[start:end]

        total_pages = max(1, ceil(total / size)) if total else 1
        has_prev = page > 1
        has_next = page < total_pages

        meta = {
                "count": total,
                "page": page,
                "page_size": size,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev,
                "next_page": page + 1 if has_next else None,
                "prev_page": page - 1 if has_prev else None,
                "next_url": _with_query(request, **{self.page_param: page + 1}) if has_next else None,
                "prev_url": _with_query(request, **{self.page_param: page - 1}) if has_prev else None,
            }
        return page_items, meta
