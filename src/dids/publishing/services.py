import shutil
import pathlib
from django.conf import settings


def _publish_root() -> pathlib.Path:
    root = getattr(settings, "DIDS_ROOT", "/app/data/dids/.well-known")
    return pathlib.Path(root).resolve()


def safe_abs_path(rel_path: str) -> pathlib.Path:
    """
    Join rel_path to DIDS_ROOT and ensure the result is contained within DIDS_ROOT.
    """
    root = _publish_root()
    target = (root / rel_path).resolve()
    if not str(target).startswith(str(root)):
        raise ValueError("Path escapes publish root")
    return target


def remove_published_folder(rel_dir: str, *, prune_empty_parents: bool = False) -> dict[str, object]:
    target = safe_abs_path(rel_dir)
    if not target.exists():
        return {"removed": False, "abs_path": str(target), "pruned": []}

    if target == _publish_root():
        raise ValueError("Refusing to remove publish root")

    shutil.rmtree(target)
    pruned: list[str] = []
    if prune_empty_parents:
        root = _publish_root()
        cur = target.parent
        while cur != root:
            try:
                next(cur.iterdir())
                break  # not empty
            except StopIteration:
                cur.rmdir()
                pruned.append(str(cur))
                cur = cur.parent

    return {"removed": True, "abs_path": str(target), "pruned": pruned}