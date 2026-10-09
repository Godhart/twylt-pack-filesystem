from __future__ import annotations
import codecs
import datetime
import fnmatch
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from charset_normalizer import from_bytes
from twylt.guardrails import WorkspaceDenied, workspace

class Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class PathInput(Model):
    path: str = Field(min_length=1, description='Virtual POSIX path relative to configured workspace root; / is the workspace, not the host root.')

class FileStats(Model):
    size_bytes: int = Field(ge=0, description='File size in bytes from filesystem metadata.')
    content_type: Literal['text', 'binary', 'unknown'] = Field(description='Conservative content classification, not MIME type.')
    line_count: int | None = Field(default=None, ge=0, description='Exact CR/LF/CRLF line count for fully decoded text; null otherwise.')
    encoding: str | None = Field(default=None, description='Codec used when content_type=text; null otherwise.')
    encoding_source: Literal['bom', 'utf8', 'explicit'] | None = Field(default=None, description='How encoding was selected for text; auto is a conservative inference, not a certainty.')
    line_ending: Literal['lf', 'crlf', 'cr', 'mixed', 'none'] | None = Field(default=None, description='Observed newline format; none means no CR/LF; null for non-text.')
    indentation: Literal['space', 'tab', 'mixed', 'none'] | None = Field(default=None, description='Leading spaces/tabs on non-blank lines; mixed across or within lines; null for non-text.')
    reason: Literal['decoded_text', 'binary_signature', 'binary_controls', 'undecodable', 'size_limit', 'file_changed']

class StatInput(PathInput):
    encoding: str = Field(default='auto', min_length=1, description='auto recognizes BOM or strict UTF-8; use an explicit codec for other encodings.')
    max_bytes: int = Field(default=16777216, ge=1, le=67108864, description='Maximum bytes read for exact classification/line count; larger files return unknown.')

class SearchInput(PathInput):
    include_stats: bool = Field(default=False, description='Attach content stats to regular files on the returned page only.')
    stats_encoding: str = Field(default='auto', min_length=1, description='Codec for included stats; auto recognizes BOM/strict UTF-8, independently of content search encoding.')
    stats_max_bytes: int = Field(default=16777216, ge=1, le=67108864, description='Per-file byte limit for included stats; larger files return unknown without affecting membership.')
    max_depth: int | None = Field(default=1, ge=0, le=1000, description='Children are depth 1; 0 returns none; null means unlimited. Root is excluded.')
    name_regex: str | None = Field(default=None, description='Python regex search on basename, case-sensitive.')
    type: Literal['file', 'directory', 'symlink', 'other'] | None = Field(default=None, description='lstat object type; symlinks are never followed.')
    permissions: str | None = Field(default=None, pattern='^[0-7]{3,4}$', description='POSIX octal mode such as 644 or 0755; unsupported on Windows.')
    permission_match: Literal['exact', 'all', 'any'] = Field(default='exact', description='Compare all mode bits, require all requested bits, or any requested bit.')
    access: str | None = Field(default=None, pattern='^[rwx]{1,3}$', description='Require current process access r/w/x using os.access; not the same as mode bits.')
    owner: str | int | None = Field(default=None, description='POSIX owner username or numeric UID; unsupported on Windows.')
    include_hidden: bool = Field(default=True, description='Include dot names and descend into dot directories; no Windows hidden-attribute handling.')
    offset: int = Field(default=0, ge=0, description='Number of matching entries to skip; zero-based.')
    limit: int = Field(default=100, ge=1, le=10000, description='Maximum entries on this page.')
    on_error: Literal['raise', 'skip'] = Field(default='raise', description='Abort on traversal/access failure, or report skipped paths in errors.')
    max_entries: int = Field(default=100000, ge=1, le=10000000, description='Abort after this many visited objects; increase for large trees.')

class RecursiveInput(SearchInput):
    max_depth: int | None = Field(default=None, ge=0, le=1000, description='Maximum depth; null searches the entire tree, root excluded.')
    path_regex: str | None = Field(default=None, description='Additional regex search on root-relative POSIX path.')

class Entry(Model):
    stats: FileStats | None = Field(default=None, description='Present for regular files when include_stats=true; null otherwise or on a reported stats error.')
    path: str
    relative_path: str
    name: str
    type: Literal['file', 'directory', 'symlink', 'other']
    depth: int
    size: int
    modified_ns: int
    permissions: str
    uid: int | None = None
    owner: str | None = None

class ScanError(Model):
    path: str
    message: str

class SearchResult(Model):
    entries: list[Entry]
    total: int = Field(description='Exact match count among successfully inspected entries, before pagination.')
    offset: int
    limit: int
    next_offset: int | None
    scanned: int
    complete: bool = Field(description='False if any paths were skipped due to errors.')
    errors: list[ScanError]
    error_count: int = Field(description='All skipped errors; errors list is capped at 100.')

class ReadBase(PathInput):
    encoding: str = Field(default='auto', description='Python codec name or auto (BOM, strict UTF-8, then heuristic detector).')
    max_bytes: int = Field(default=16777216, ge=1, le=67108864, description='Maximum entire source file size to decode, even for a line slice.')

class TransferInput(Model):
    source: str = Field(min_length=1, description='Virtual source path within workspace; regular files and directories only.')
    destination: str = Field(min_length=1, description='Virtual exact destination within workspace, never an implicit containing directory.')
    overwrite: bool = Field(default=False, description='Replace an existing regular file only; existing directories/symlinks are refused.')
    create_parents: bool = Field(default=False, description='Create missing destination parent directories.')

class MutationResult(Model):
    operation: str
    path: str
    source: str | None = None
    changed: bool
    bytes_written: int | None = None

def absolute(value):
    return workspace().resolve(value)

def kind(mode):
    if stat.S_ISLNK(mode):
        return 'symlink'
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISDIR(mode):
        return 'directory'
    return 'other'

def glob_matcher(pattern):
    if pattern.startswith('/') or '\\' in pattern or any((p in ('', '.', '..') for p in pattern.split('/'))):
        raise ValueError('pattern must be a relative POSIX glob without empty, . or .. segments')
    parts = pattern.split('/')
    if any(('**' in part and part != '**' for part in parts)):
        raise ValueError('** must occupy a whole path segment')

    def matches(path):
        from functools import lru_cache
        segments = path.split('/')

        @lru_cache(None)
        def visit(i, j):
            if i == len(parts):
                return j == len(segments)
            if parts[i] == '**':
                return visit(i + 1, j) or (j < len(segments) and visit(i, j + 1))
            return j < len(segments) and fnmatch.fnmatchcase(segments[j], parts[i]) and visit(i + 1, j + 1)
        return visit(0, 0)
    return matches

def search(data):
    root = absolute(data.path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Search root must be a real directory, not a symlink')
    if os.name != 'posix' and (data.owner is not None or data.permissions is not None):
        raise ValueError('owner and permissions filters require POSIX')
    uid = data.owner
    pwd_module = None
    if os.name == 'posix':
        import pwd as pwd_module
        if isinstance(uid, str):
            uid = pwd_module.getpwnam(uid).pw_uid
    name_rx = re.compile(data.name_regex) if data.name_regex is not None else None
    path_rx = re.compile(getattr(data, 'path_regex', None)) if getattr(data, 'path_regex', None) is not None else None
    glob_rx = glob_matcher(data.pattern) if hasattr(data, 'pattern') else None
    if data.include_stats and data.stats_encoding != 'auto':
        codecs.lookup(data.stats_encoding)
    content = getattr(data, 'content', None)
    content_rx = None
    if content is not None:
        if content.encoding != 'auto':
            codecs.lookup(content.encoding)
        content_rx = re.compile(content.query if content.regex else re.escape(content.query), re.IGNORECASE if content.ignore_case else 0)
    wanted_mode = int(data.permissions, 8) if data.permissions is not None else None
    access_mode = sum(({'r': os.R_OK, 'w': os.W_OK, 'x': os.X_OK}[x] for x in set(data.access or '')))
    entries, errors, owners = ([], [], {})
    total = scanned = error_count = 0

    def record_error(path, exc):
        nonlocal error_count
        if data.on_error == 'raise':
            raise exc
        error_count += 1
        if len(errors) < 100:
            errors.append(ScanError(path=workspace().virtual(path), message=workspace().redact(exc)))
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if data.max_depth is not None and depth >= data.max_depth:
            continue
        try:
            workspace().inspect(directory)
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda e: e.name)
        except OSError as exc:
            record_error(directory, exc)
            continue
        descend = []
        for item in children:
            if not data.include_hidden and item.name.startswith('.'):
                continue
            scanned += 1
            if scanned > data.max_entries:
                raise ValueError('max_entries exceeded; narrow search or increase the limit')
            path = workspace().inspect(Path(item.path), allow_leaf_link=True)
            try:
                st = item.stat(follow_symlinks=False)
            except OSError as exc:
                record_error(path, exc)
                continue
            obj_type = kind(st.st_mode)
            if obj_type == 'directory':
                descend.append((path, depth + 1))
            rel = path.relative_to(root).as_posix()
            if data.type is not None and obj_type != data.type:
                continue
            if name_rx is not None and (not name_rx.search(item.name)):
                continue
            if path_rx is not None and (not path_rx.search(rel)):
                continue
            if glob_rx is not None and (not glob_rx(rel)):
                continue
            if uid is not None and st.st_uid != uid:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if wanted_mode is not None:
                matches = {'exact': mode == wanted_mode, 'all': mode & wanted_mode == wanted_mode, 'any': bool(mode & wanted_mode)}
                if not matches[data.permission_match]:
                    continue
            if data.access is not None:
                if obj_type == 'symlink' or not os.access(path, access_mode):
                    continue
            if content is not None:
                if obj_type != 'file':
                    continue
                try:
                    _, text, _ = decode_file(ReadBase(path=workspace().virtual(path), encoding=content.encoding, max_bytes=content.max_bytes))
                    if '\x00' in text:
                        raise BinaryContentError('NUL in decoded text; binary content excluded')
                except WorkspaceDenied:
                    raise
                except BinaryContentError as exc:
                    if content.skip_binary:
                        continue
                    record_error(path, exc)
                    continue
                except (OSError, ValueError) as exc:
                    record_error(path, exc)
                    continue
                if not content_rx.search(text):
                    continue
            if data.offset <= total < data.offset + data.limit:
                file_stats = None
                if data.include_stats and obj_type == 'file':
                    try:
                        file_stats = inspect_file(StatInput(path=workspace().virtual(path), encoding=data.stats_encoding, max_bytes=data.stats_max_bytes))
                    except WorkspaceDenied:
                        raise
                    except OSError as exc:
                        record_error(path, exc)
                owner_id = st.st_uid if os.name == 'posix' else None
                if pwd_module is not None and owner_id not in owners:
                    try:
                        owners[owner_id] = pwd_module.getpwuid(owner_id).pw_name
                    except KeyError:
                        owners[owner_id] = None
                entries.append(Entry(path=workspace().virtual(path), relative_path=rel, name=item.name, type=obj_type, depth=depth + 1, size=st.st_size, modified_ns=st.st_mtime_ns, permissions=format(mode, '04o'), uid=owner_id, owner=owners.get(owner_id), stats=file_stats))
            total += 1
        stack.extend(reversed(descend))
    return SearchResult(entries=entries, total=total, offset=data.offset, limit=data.limit, next_offset=data.offset + data.limit if data.offset + data.limit < total else None, scanned=scanned, complete=error_count == 0, errors=errors, error_count=error_count)

class BinaryContentError(ValueError):
    pass

def decode_file(data):
    path = absolute(data.path)
    if not path.is_file():
        raise ValueError('Expected a regular file')
    with path.open('rb') as stream:
        raw = stream.read(data.max_bytes + 1)
    if len(raw) > data.max_bytes:
        raise ValueError('File exceeds max_bytes')
    encoding = data.encoding
    if encoding == 'auto':
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            encoding = 'utf-32'
        elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encoding = 'utf-16'
        elif raw.startswith(codecs.BOM_UTF8):
            encoding = 'utf-8-sig'
        else:
            if b'\x00' in raw:
                raise BinaryContentError('NUL bytes: binary file or text requiring explicit encoding')
            try:
                raw.decode('utf-8')
                encoding = 'utf-8'
            except UnicodeDecodeError:
                match = from_bytes(raw).best()
                if match is None:
                    raise ValueError('Unable to detect encoding; supply encoding explicitly')
                encoding = match.encoding
    return (path, raw.decode(encoding, errors='strict'), encoding)

def file_format(data):
    if data.format != 'auto':
        return data.format
    suffix = Path(data.path).suffix.lower()
    formats = {'.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml'}
    if suffix not in formats:
        raise ValueError('Cannot infer format; specify json, yaml or toml')
    return formats[suffix]

def normalize(value, active=None):
    active = set() if active is None else active
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            raise ValueError('Non-finite numbers are not JSON-compatible')
        return value
    if isinstance(value, (list, dict)):
        if id(value) in active:
            raise ValueError('Recursive YAML aliases are not supported')
        active.add(id(value))
        try:
            if isinstance(value, list):
                return [normalize(v, active) for v in value]
            if any((not isinstance(k, str) for k in value)):
                raise ValueError('Mapping keys must be strings')
            return {k: normalize(v, active) for k, v in value.items()}
        finally:
            active.remove(id(value))
    raise ValueError('Unsupported value type: ' + type(value).__name__)

def write_bytes(data, payload, operation):
    path = absolute(data.path)
    if path.is_symlink() or (path.exists() and (not path.is_file())):
        raise ValueError('Target must be a regular file, not a symlink')
    if path.exists() and (not data.overwrite):
        raise FileExistsError(str(path))
    if data.create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    old_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.fs-twylt-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if old_mode is not None:
            os.chmod(temporary, old_mode)
        if data.overwrite:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return MutationResult(operation=operation, path=workspace().virtual(path), changed=True, bytes_written=len(payload))

def transfer(data, operation):
    source, destination = (absolute(data.source), absolute(data.destination))
    workspace().protect_root(destination)
    if operation == 'move':
        workspace().protect_root(source)
    workspace().tree(source)
    if not os.path.lexists(source):
        raise FileNotFoundError(str(source))
    src_kind = kind(source.lstat().st_mode)
    if src_kind == 'other':
        raise ValueError('Special files are not supported')
    if source == destination or (source.exists() and destination.exists() and os.path.samefile(source, destination)):
        raise ValueError('Source and destination are the same object')
    resolved_source, resolved_dest = (source.resolve(), destination.resolve())
    if src_kind == 'directory' and (resolved_dest == resolved_source or resolved_source in resolved_dest.parents):
        raise ValueError('Destination cannot be inside source directory')
    if os.path.lexists(destination):
        if not data.overwrite:
            raise FileExistsError(str(destination))
        if destination.is_symlink() or not destination.is_file() or src_kind == 'directory':
            raise ValueError('Only an existing regular file may be overwritten by a file or link')
    if data.create_parents:
        destination.parent.mkdir(parents=True, exist_ok=True)
    if operation == 'move':
        shutil.move(str(source), str(destination))
    elif src_kind == 'directory':
        shutil.copytree(source, destination, symlinks=True)
    elif src_kind == 'symlink':
        if destination.exists():
            raise ValueError('Copying a symlink requires an absent destination')
        os.symlink(os.readlink(source), destination, target_is_directory=source.is_dir())
    else:
        fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix='.fs-twylt-')
        os.close(fd)
        try:
            shutil.copy2(source, temporary)
            if data.overwrite:
                os.replace(temporary, destination)
            else:
                os.link(temporary, destination)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
    return MutationResult(operation=operation, path=workspace().virtual(destination), source=workspace().virtual(source), changed=True)

_BINARY_SIGNATURES = (b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'GIF87a', b'GIF89a', b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x7fELF', b'\x1f\x8b', b'%PDF-', b'\x00asm')

def inspect_file(data):
    path = absolute(data.path)
    if data.encoding != 'auto':
        codecs.lookup(data.encoding)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('fs_stat requires a regular file')

    def result(content_type, reason, **kwargs):
        return FileStats(size_bytes=before.st_size, content_type=content_type, reason=reason, **kwargs)
    if before.st_size > data.max_bytes:
        return result('unknown', 'size_limit')
    with path.open('rb') as stream:
        raw = stream.read(data.max_bytes + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        return result('unknown', 'file_changed')
    if len(raw) > data.max_bytes:
        return result('unknown', 'size_limit')
    if len(raw) != before.st_size:
        return result('unknown', 'file_changed')
    if raw.startswith(_BINARY_SIGNATURES):
        return result('binary', 'binary_signature')
    encoding = data.encoding
    encoding_source = 'explicit'
    if encoding == 'auto':
        encoding_source = 'bom'
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            encoding = 'utf-32'
        elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encoding = 'utf-16'
        elif raw.startswith(codecs.BOM_UTF8):
            encoding = 'utf-8-sig'
        else:
            if b'\x00' in raw or re.search(b'[\\x01-\\x08\\x0b\\x0e-\\x1f\\x7f]', raw):
                return result('binary', 'binary_controls')
            encoding = 'utf-8'
            encoding_source = 'utf8'
    try:
        text = raw.decode(encoding, errors='strict')
    except UnicodeError:
        return result('unknown', 'undecodable')
    if re.search('[\\x00-\\x08\\x0b\\x0e-\\x1f\\x7f-\\x9f]', text):
        return result('binary', 'binary_controls')
    lines = sum((1 for _ in re.finditer('\\r\\n|\\r|\\n', text)))
    if text and (not text.endswith(('\r', '\n'))):
        lines += 1
    endings = set(re.findall('\\r\\n|\\r|\\n', text))
    newline_names = {'\r\n': 'crlf', '\n': 'lf', '\r': 'cr'}
    line_ending = 'none' if not endings else newline_names[next(iter(endings))] if len(endings) == 1 else 'mixed'
    indent_chars = set()
    for line in re.split('\\r\\n|\\r|\\n', text):
        if not line.strip():
            continue
        leading = re.match('[ \\t]*', line).group()
        indent_chars.update(leading)
    indentation = 'mixed' if len(indent_chars) == 2 else 'space' if ' ' in indent_chars else 'tab' if '\t' in indent_chars else 'none'
    return result('text', 'decoded_text', encoding=encoding, line_count=lines, encoding_source=encoding_source, line_ending=line_ending, indentation=indentation)
