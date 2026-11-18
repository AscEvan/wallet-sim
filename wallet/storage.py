from __future__ import annotations

import copy
import json 
import os
import pathlib

DEFAULT_SCHEMA_VERSION: int = 1


class StorageError(ValueError):
    """dilempar jika file JSON rusak, bukan dict, atau versi tidak didukung """


def write_json_atomic(path: str | pathlib.Path, data: dict, *, expected_version: int = DEFAULT_SCHEMA_VERSION) -> None:
    if not isinstance(data, dict):
        raise TypeError(f'data harus bentuk dict, dapat: {type(data)}')

    if data.get('version') != expected_version:
        raise StorageError(f"versi tidak valid, diharapkan: {expected_version}, dapat: {data.get('version')}")

    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_suffix(target.suffix + ".tmp")

    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, target)

def read_json(path: str | pathlib.Path, *, expected_version: int = DEFAULT_SCHEMA_VERSION, default: dict | None = None) -> dict:
    target = pathlib.Path(path)
    if not target.exists():
        if default is not None:
            return copy.deepcopy(default)
        elif default is None:
            raise FileNotFoundError(f'file tidak ditemukan: {target}')
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))

    except json.JSONDecodeError:
        raise StorageError('file json error')
    
    if not isinstance(data, dict):
        raise StorageError(f'file data harus bentuk dict, dapat: {type(data)}')
    
    if data.get('version') != expected_version:
        raise StorageError(f"versi tidak didukung, expect: {expected_version}; aktual: {data.get('version')}")
    
    return data


    