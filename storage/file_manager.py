from pathlib import Path
import json
import os
import shutil
import tempfile
from typing import Iterable, Optional
import uuid

from .models import FileMetadata

VAULT_ROOT = Path("vault")

# helper methods

def _canon_username(username: str) -> str:
    username = username.strip()
    if not username:
        raise ValueError("username cannot be empty")
    return username.lower()

def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def _user_dir(username: str, root: Path = VAULT_ROOT) -> Path:
    return _ensure_dir(root / _canon_username(username))

def _index_path(user_dir: Path) -> Path:
    return user_dir / "index.json"

def _load_index(user_dir: Path) -> list[FileMetadata]:
    path = _index_path(user_dir)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [FileMetadata.from_dict(item) for item in data.get("files", [])]

def _save_index(user_dir: Path, entries: Iterable[FileMetadata]) -> None:
    path = _index_path(user_dir)
    payload = {"files": [entry.to_dict() for entry in entries]}
    fd, tmp = tempfile.mkstemp(prefix="vault.", suffix=".json", dir=str(user_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        Path(tmp).replace(path)
    finally:
        tmp_path = Path(tmp)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

def _select_entry(entries: Iterable[FileMetadata], identifier: str) -> Optional[FileMetadata]:
    for entry in entries:
        if entry.file_id == identifier or entry.filename == identifier:
            return entry
    return None

def _default_download_dir(username: str) -> Path:
    base = Path.home() / "Downloads"
    return base / _canon_username(username)

# public operations

def list_files(username: str, *, vault_root: Path = VAULT_ROOT) -> list[FileMetadata]:
    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

def upload_file(username: str, filepath: str, *, vault_root: Path = VAULT_ROOT) -> FileMetadata:
    src = Path(filepath).expanduser()
    if not src.is_file():
        raise FileNotFoundError(f"{filepath} is not a file")

    user_dir = _user_dir(username, vault_root)

    stored_name = f"{uuid.uuid4().hex}{src.suffix or ''}.bin"
    entry = FileMetadata.new(
        owner=_canon_username(username),
        filename=src.name,
        stored_name=stored_name,
        size=src.stat().st_size,
    )

    shutil.copy2(src, user_dir / stored_name)

    entries = _load_index(user_dir)
    entries.append(entry)
    _save_index(user_dir, entries)
    return entry

def download_file(
    username: str,
    filename: str,
    dest_dir: Optional[str] = None,
    *,
    vault_root: Path = VAULT_ROOT,
) -> Path:
    if not filename:
        raise ValueError("filename cannot be empty")

    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    entry = _select_entry(entries, filename)
    
    if not entry:
        raise FileNotFoundError(f"No stored file named '{filename}' for {username}")

    source_path = user_dir / entry.stored_name
    if not source_path.exists():
        raise FileNotFoundError(f"Stored blob missing: {source_path}")


    if dest_dir:
        target_dir = _ensure_dir(Path(dest_dir).expanduser())
    else:
        target_dir = _ensure_dir(_default_download_dir(username))

    _ensure_dir(target_dir)
    target_path = target_dir / entry.filename
    shutil.copy2(source_path, target_path)
    return target_path
