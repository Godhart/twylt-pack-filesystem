"""Canonical shared implementation; embedded into each generated tool.py."""
from __future__ import annotations
import codecs
import datetime
import fnmatch
import json
import os
import re
import shutil
import stat
import tempfile
import tomllib
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator
from twylt import Tool, Requirements
import yaml
import tomli_w
from charset_normalizer import from_bytes
from markdown_it import MarkdownIt

"""Shared workspace policy 1.0.0. Embedded verbatim in standalone tools.
Explicit path confinement, not an OS sandbox. Environment is trusted configuration.
"""
import contextvars
import datetime as _datetime
import json as _json
import os as _os
from pathlib import Path as _Path
import stat as _stat
import sys as _sys
import uuid as _uuid

_POLICY = contextvars.ContextVar('twylt_workspace', default=None)

class WorkspaceDenied(ValueError):
    """A policy denial, already recorded in the incident sink."""
    def __init__(self, code, incident_id):
        self.code = code
        self.incident_id = incident_id
        super().__init__(f'{code}: access denied (incident {incident_id})')

class Workspace:
    def __init__(self, tool='unknown'):
        self.tool = tool
        self.log_path = None
        self.root = None
        value = _os.environ.get('TWYLT_WORKSPACE_ROOT', '')
        if not value or not _Path(value).is_absolute():
            self.deny('workspace_not_configured')
        candidate = _Path(_os.path.abspath(value))
        # The root and all of its ancestors must be real directories.
        try:
            for part in [*reversed(candidate.parents), candidate]:
                st = part.lstat()
                if self._link(st) or not _stat.S_ISDIR(st.st_mode):
                    self.deny('invalid_workspace_root')
            if candidate.parent == candidate:
                self.deny('filesystem_root_forbidden')
        except OSError:
            self.deny('invalid_workspace_root')
        self.root = candidate
        configured_log = _os.environ.get('TWYLT_INCIDENT_LOG', '')
        if configured_log:
            p = _Path(configured_log)
            if not p.is_absolute(): self.deny('invalid_incident_log')
            p = _Path(_os.path.abspath(p))
            if self.contains(p): self.deny('incident_log_inside_workspace')
            try:
                for parent in [*reversed(p.parent.parents), p.parent]:
                    st = parent.lstat()
                    if self._link(st) or not _stat.S_ISDIR(st.st_mode):
                        self.deny('invalid_incident_log')
                self.log_path = p
                fd = self._open_log()
                _os.close(fd)
            except WorkspaceDenied:
                raise
            except (OSError, ValueError):
                self.log_path = None
                self.deny('incident_log_unavailable')

    @staticmethod
    def _link(st):
        # Includes Windows junctions/reparse points even on Python without is_junction().
        return _stat.S_ISLNK(st.st_mode) or bool(getattr(st, 'st_file_attributes', 0) & 0x400)

    def contains(self, path):
        return self.root is not None and (path == self.root or self.root in path.parents)

    def _open_log(self):
        p = self.log_path
        if p.exists() or p.is_symlink():
            st = p.lstat()
            if self._link(st) or not _stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('unsafe audit sink')
        flags = _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT | getattr(_os, 'O_NOFOLLOW', 0) | getattr(_os, 'O_CLOEXEC', 0) | getattr(_os, 'O_NONBLOCK', 0)
        fd = _os.open(p, flags, 0o600)
        try:
            st = _os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('unsafe audit sink')
        except BaseException:
            _os.close(fd)
            raise
        return fd

    def deny(self, code, requested=None):
        identifier = str(_uuid.uuid4())
        event = {'event': 'workspace_incident', 'schema_version': '1.0',
                 'timestamp': _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
                 'incident_id': identifier, 'tool': self.tool, 'pid': _os.getpid(),
                 'action': 'deny', 'code': code}
        if requested is not None:
            # Only explicit path values, never file contents or remote URLs/credentials.
            event['requested_path'] = str(requested)[:1024]
        payload = (_json.dumps(event, ensure_ascii=True, separators=(',', ':')) + '\n').encode('utf-8')
        try:
            if self.log_path is None:
                _sys.stderr.write(payload.decode('utf-8')); _sys.stderr.flush()
            else:
                fd = self._open_log()
                try:
                    if _os.write(fd, payload) != len(payload): raise OSError('short audit write')
                    _os.fsync(fd)
                finally: _os.close(fd)
        except (OSError, ValueError):
            event['original_code'] = code
            event['code'] = code = 'incident_log_unavailable'
            _sys.stderr.write(_json.dumps(event, ensure_ascii=True) + '\n'); _sys.stderr.flush()
        raise WorkspaceDenied(code, identifier)

    def inspect(self, path, allow_leaf_link=False):
        """Check physical path components without following any link."""
        path = _Path(path)
        if not self.contains(path): self.deny('path_outside_workspace')
        current = self.root
        parts = path.relative_to(self.root).parts
        for i, part in enumerate(parts):
            current = current / part
            try: st = current.lstat()
            except FileNotFoundError: break
            if self._link(st):
                if allow_leaf_link and i == len(parts)-1: return path
                self.deny('symlink_forbidden', self.virtual_unchecked(path))
            if _stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                self.deny('hardlink_forbidden', self.virtual_unchecked(path))
            if not (_stat.S_ISREG(st.st_mode) or _stat.S_ISDIR(st.st_mode)):
                self.deny('special_file_forbidden', self.virtual_unchecked(path))
            if st.st_dev != self.root.stat().st_dev:
                self.deny('mount_boundary_forbidden', self.virtual_unchecked(path))
        return path

    def resolve(self, value, base=None):
        """POSIX virtual / is root; relative paths are root-based unless base is explicit."""
        if not isinstance(value, str) or not value or '\x00' in value:
            self.deny('invalid_path')
        if '\\' in value or ':' in value or value.startswith('//') or value.startswith('~'):
            self.deny('invalid_path_syntax', value)
        parts = value.split('/')
        if '..' in parts: self.deny('path_outside_workspace', value)
        if _os.name == 'nt':
            reserved = {'CON','PRN','AUX','NUL', *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))}
            if any(p.endswith((' ', '.')) or p.split('.')[0].upper() in reserved for p in parts if p not in {'', '.'}):
                self.deny('invalid_path_syntax', value)
        start = self.root if value.startswith('/') or base is None else base
        path = start.joinpath(*(p for p in parts if p not in {'', '.'}))
        return self.inspect(path)

    def virtual_unchecked(self, path):
        relative = _Path(path).relative_to(self.root).as_posix()
        return '/' if relative == '.' else '/' + relative

    def virtual(self, path):
        if not self.contains(_Path(path)): self.deny('path_outside_workspace')
        return self.virtual_unchecked(path)

    def protect_root(self, path):
        if path == self.root: self.deny('workspace_root_mutation_forbidden', '/')

    def tree(self, path):
        """Preflight every descendant before a recursive mutation."""
        self.inspect(path)
        if not path.is_dir(): return
        stack = [path]
        while stack:
            parent = stack.pop()
            with _os.scandir(parent) as children:
                for child in children:
                    p = self.inspect(_Path(child.path))
                    if p.is_dir(): stack.append(p)

    def redact(self, value):
        if self.root is None: return str(value)
        return str(value).replace(str(self.root) + _os.sep, '/').replace(str(self.root), '/')

    def __enter__(self):
        self._token = _POLICY.set(self)
        return self

    def __exit__(self, typ, exc, tb):
        _POLICY.reset(self._token)
        # Remove host workspace prefixes from errors returned by business code.
        if exc is not None and not isinstance(exc, WorkspaceDenied):
            if isinstance(exc, OSError):
                if exc.filename: exc.filename = self.redact(exc.filename)
                if exc.filename2: exc.filename2 = self.redact(exc.filename2)
            exc.args = tuple(self.redact(a) if isinstance(a, str) else a for a in exc.args)
        return False

def workspace():
    active = _POLICY.get()
    return active if active is not None else Workspace()

class WorkspaceTransport:
    """Guard TWYLT 1.0.0's implicit input.json/output.json before its file I/O."""
    @classmethod
    def _transport_payload(cls):
        payload, source = super()._transport_payload()
        if source is None and not _os.environ.get('INPUT_DESCRIBE', ''):
            with Workspace(cls.name) as ws:
                cwd = _Path.cwd()
                if not ws.contains(cwd): ws.deny('transport_cwd_outside_workspace')
                ws.inspect(cwd)
                for attribute in ['input_path', 'output_path']:
                    path = _Path(getattr(cls, attribute))
                    full = path if path.is_absolute() else cwd/path
                    setattr(cls, attribute, ws.inspect(full))
        return payload, source

    @classmethod
    def _write_output(cls, value):
        with Workspace(cls.name) as ws:
            ws.inspect(_Path(cls.output_path))
            return super()._write_output(value)


VERSION = '0.5.0'

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

class StatResult(FileStats):
    path: str

class ChmodInput(PathInput):
    mode: str = Field(pattern=r'^[0-7]{3,4}$', description='Exact POSIX octal mode, e.g. 644, 0755 or 0640; no symbolic or recursive mode.')
    dry_run: bool = Field(default=False, description='Report requested mode without applying it.')

class ChmodResult(Model):
    path: str
    previous_mode: str
    requested_mode: str
    mode: str = Field(description='Actual current mode after operation, or original mode for dry_run.')
    changed: bool
    dry_run: bool

class SearchInput(PathInput):
    include_stats: bool = Field(default=False, description='Attach content stats to regular files on the returned page only.')
    stats_encoding: str = Field(default='auto', min_length=1, description='Codec for included stats; auto recognizes BOM/strict UTF-8, independently of content search encoding.')
    stats_max_bytes: int = Field(default=16777216, ge=1, le=67108864, description='Per-file byte limit for included stats; larger files return unknown without affecting membership.')
    max_depth: int | None = Field(default=1, ge=0, le=1000, description='Children are depth 1; 0 returns none; null means unlimited. Root is excluded.')
    name_regex: str | None = Field(default=None, description='Python regex search on basename, case-sensitive.')
    type: Literal['file', 'directory', 'symlink', 'other'] | None = Field(default=None, description='lstat object type; symlinks are never followed.')
    permissions: str | None = Field(default=None, pattern=r'^[0-7]{3,4}$', description='POSIX octal mode such as 644 or 0755; unsupported on Windows.')
    permission_match: Literal['exact', 'all', 'any'] = Field(default='exact', description='Compare all mode bits, require all requested bits, or any requested bit.')
    access: str | None = Field(default=None, pattern=r'^[rwx]{1,3}$', description='Require current process access r/w/x using os.access; not the same as mode bits.')
    owner: str | int | None = Field(default=None, description='POSIX owner username or numeric UID; unsupported on Windows.')
    include_hidden: bool = Field(default=True, description='Include dot names and descend into dot directories; no Windows hidden-attribute handling.')
    offset: int = Field(default=0, ge=0, description='Number of matching entries to skip; zero-based.')
    limit: int = Field(default=100, ge=1, le=10000, description='Maximum entries on this page.')
    on_error: Literal['raise', 'skip'] = Field(default='raise', description='Abort on traversal/access failure, or report skipped paths in errors.')
    max_entries: int = Field(default=100000, ge=1, le=10000000, description='Abort after this many visited objects; increase for large trees.')

class RecursiveInput(SearchInput):
    max_depth: int | None = Field(default=None, ge=0, le=1000, description='Maximum depth; null searches the entire tree, root excluded.')
    path_regex: str | None = Field(default=None, description='Additional regex search on root-relative POSIX path.')

class ContentFilter(Model):
    query: str = Field(min_length=1, description='Non-empty literal text or Python regex searched across the whole decoded file.')
    regex: bool = Field(default=False, description='Treat query as Python regex; otherwise metacharacters are literal.')
    ignore_case: bool = Field(default=False, description='Use Unicode case-insensitive matching.')
    encoding: str = Field(default='auto', min_length=1, description='Python codec or auto, using the same detection as fs_read.')
    max_bytes: int = Field(default=16777216, ge=1, le=67108864, description='Maximum source bytes per file; larger candidates follow on_error.')
    skip_binary: bool = Field(default=True, description='Exclude files containing NUL in decoded text or non-BOM auto input; false reports an error.')

class FindInput(RecursiveInput):
    content: ContentFilter | None = Field(default=None, description='Optional full-text filter. Returns matching regular files, combined with all metadata filters using AND.')
    @model_validator(mode='after')
    def content_type(self):
        if self.content is not None and self.type not in (None, 'file'):
            raise ValueError('content requires type=file or omitted type')
        return self

class GlobInput(RecursiveInput):
    pattern: str = Field(min_length=1, description='Relative POSIX glob: *, ?, [], and ** as an entire segment. ** matches zero or more segments.')

class Entry(Model):
    stats: FileStats | None = Field(default=None, description="Present for regular files when include_stats=true; null otherwise or on a reported stats error.")
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

class ReadInput(ReadBase):
    offset: int = Field(default=0, ge=0, description='Zero-based number of lines to skip.')
    count: int | None = Field(default=200, ge=0, le=1000000, description='Maximum lines returned; null reads all remaining lines within max_bytes.')

class ReadResult(Model):
    path: str
    encoding: str
    detected: bool
    text: str = Field(description='Selected lines with original newline characters preserved.')
    offset: int
    lines_returned: int
    total_lines: int
    next_offset: int | None

class JytInput(ReadBase):
    format: Literal['auto', 'json', 'yaml', 'toml'] = Field(default='auto', description='auto uses the filename extension .json/.yaml/.yml/.toml.')

class JytResult(Model):
    path: str
    format: str
    encoding: str
    data: JsonValue

class MarkdownInput(ReadBase):
    pass

class MarkdownResult(Model):
    path: str
    encoding: str
    nodes: list[dict[str, JsonValue]] = Field(description='Nested markdown-it token AST; source line ranges are zero-based, end-exclusive.')

class WriteInput(PathInput):
    content: str = Field(description='Complete text to write, without implicit newline changes.')
    encoding: str = Field(default='utf-8', description='Explicit Python codec; auto is not supported for writing.')
    overwrite: bool = Field(default=False, description='Allow atomic replacement of an existing regular file.')
    create_parents: bool = Field(default=False, description='Create missing parent directories.')

class WriteJytInput(PathInput):
    data: JsonValue = Field(description='JSON-compatible structure; TOML requires an object and cannot represent null.')
    format: Literal['auto', 'json', 'yaml', 'toml'] = Field(default='auto', description='auto infers format from extension.')
    encoding: str = Field(default='utf-8', description='Explicit Python codec; use UTF-8 for interoperable JSON/YAML/TOML.')
    overwrite: bool = Field(default=False, description='Explicitly allow replacing an existing regular file.')
    create_parents: bool = Field(default=False, description='Create missing parent directories.')
    indent: int = Field(default=2, ge=1, le=8, description='Indentation for JSON/YAML; TOML writer controls its own layout.')

class TransferInput(Model):
    source: str = Field(min_length=1, description='Virtual source path within workspace; regular files and directories only.')
    destination: str = Field(min_length=1, description='Virtual exact destination within workspace, never an implicit containing directory.')
    overwrite: bool = Field(default=False, description='Replace an existing regular file only; existing directories/symlinks are refused.')
    create_parents: bool = Field(default=False, description='Create missing destination parent directories.')

class DeleteInput(PathInput):
    recursive: bool = Field(default=False, description='Required for non-empty directories; symlinks and workspace root are refused.')
    missing_ok: bool = Field(default=False, description='Succeed if the path does not exist.')
    dry_run: bool = Field(default=False, description='Validate and report the target without removing it.')

class MutationResult(Model):
    operation: str
    path: str
    source: str | None = None
    changed: bool
    bytes_written: int | None = None


def absolute(value):
    return workspace().resolve(value)


def kind(mode):
    if stat.S_ISLNK(mode): return 'symlink'
    if stat.S_ISREG(mode): return 'file'
    if stat.S_ISDIR(mode): return 'directory'
    return 'other'


def glob_matcher(pattern):
    if pattern.startswith('/') or '\\' in pattern or any(p in ('', '.', '..') for p in pattern.split('/')):
        raise ValueError('pattern must be a relative POSIX glob without empty, . or .. segments')
    parts = pattern.split('/')
    if any('**' in part and part != '**' for part in parts):
        raise ValueError('** must occupy a whole path segment')
    def matches(path):
        from functools import lru_cache
        segments = path.split('/')
        @lru_cache(None)
        def visit(i, j):
            if i == len(parts): return j == len(segments)
            if parts[i] == '**':
                return visit(i+1, j) or (j < len(segments) and visit(i, j+1))
            return j < len(segments) and fnmatch.fnmatchcase(segments[j], parts[i]) and visit(i+1, j+1)
        return visit(0, 0)
    return matches


def search(data):
    root = absolute(data.path)
    if root.is_symlink() or not root.is_dir(): raise ValueError('Search root must be a real directory, not a symlink')
    if os.name != 'posix' and (data.owner is not None or data.permissions is not None):
        raise ValueError('owner and permissions filters require POSIX')
    uid = data.owner
    pwd_module = None
    if os.name == 'posix':
        import pwd as pwd_module
        if isinstance(uid, str): uid = pwd_module.getpwnam(uid).pw_uid
    name_rx = re.compile(data.name_regex) if data.name_regex is not None else None
    path_rx = re.compile(getattr(data, 'path_regex', None)) if getattr(data, 'path_regex', None) is not None else None
    glob_rx = glob_matcher(data.pattern) if hasattr(data, "pattern") else None
    if data.include_stats and data.stats_encoding != 'auto': codecs.lookup(data.stats_encoding)
    content = getattr(data, 'content', None)
    content_rx = None
    if content is not None:
        if content.encoding != 'auto': codecs.lookup(content.encoding)
        content_rx = re.compile(content.query if content.regex else re.escape(content.query), re.IGNORECASE if content.ignore_case else 0)
    wanted_mode = int(data.permissions, 8) if data.permissions is not None else None
    access_mode = sum({'r': os.R_OK, 'w': os.W_OK, 'x': os.X_OK}[x] for x in set(data.access or ''))
    entries, errors, owners = [], [], {}
    total = scanned = error_count = 0
    def record_error(path, exc):
        nonlocal error_count
        if data.on_error == 'raise': raise exc
        error_count += 1
        if len(errors) < 100: errors.append(ScanError(path=workspace().virtual(path), message=workspace().redact(exc)))
    # Explicit stack avoids Python recursion limits; order is sorted depth-first preorder.
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if data.max_depth is not None and depth >= data.max_depth: continue
        try:
            workspace().inspect(directory)
            with os.scandir(directory) as iterator: children = sorted(iterator, key=lambda e: e.name)
        except OSError as exc:
            record_error(directory, exc)
            continue
        descend = []
        for item in children:
            if not data.include_hidden and item.name.startswith('.'): continue
            scanned += 1
            if scanned > data.max_entries: raise ValueError('max_entries exceeded; narrow search or increase the limit')
            path = workspace().inspect(Path(item.path), allow_leaf_link=True)
            try: st = item.stat(follow_symlinks=False)
            except OSError as exc:
                record_error(path, exc)
                continue
            obj_type = kind(st.st_mode)
            if obj_type == 'directory': descend.append((path, depth+1))
            rel = path.relative_to(root).as_posix()
            if data.type is not None and obj_type != data.type: continue
            if name_rx is not None and not name_rx.search(item.name): continue
            if path_rx is not None and not path_rx.search(rel): continue
            if glob_rx is not None and not glob_rx(rel): continue
            if uid is not None and st.st_uid != uid: continue
            mode = stat.S_IMODE(st.st_mode)
            if wanted_mode is not None:
                matches = {'exact': mode == wanted_mode, 'all': mode & wanted_mode == wanted_mode, 'any': bool(mode & wanted_mode)}
                if not matches[data.permission_match]: continue
            if data.access is not None:
                # Never follow symlinks merely to evaluate an access filter.
                if obj_type == 'symlink' or not os.access(path, access_mode): continue
            if content is not None:
                if obj_type != 'file': continue
                try:
                    # Revalidate immediately before opening, using the shared reader.
                    _, text, _ = decode_file(ReadBase(path=workspace().virtual(path), encoding=content.encoding, max_bytes=content.max_bytes))
                    if '\x00' in text: raise BinaryContentError('NUL in decoded text; binary content excluded')
                except WorkspaceDenied:
                    raise  # Policy incidents must never be suppressed by on_error=skip.
                except BinaryContentError as exc:
                    if content.skip_binary: continue
                    record_error(path, exc)
                    continue
                except (OSError, ValueError) as exc:
                    record_error(path, exc)
                    continue
                if not content_rx.search(text): continue
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
                    try: owners[owner_id] = pwd_module.getpwuid(owner_id).pw_name
                    except KeyError: owners[owner_id] = None
                entries.append(Entry(path=workspace().virtual(path), relative_path=rel, name=item.name, type=obj_type,
                    depth=depth+1, size=st.st_size, modified_ns=st.st_mtime_ns,
                    permissions=format(mode, '04o'), uid=owner_id, owner=owners.get(owner_id), stats=file_stats))
            total += 1
        stack.extend(reversed(descend))
    return SearchResult(entries=entries, total=total, offset=data.offset, limit=data.limit,
        next_offset=data.offset+data.limit if data.offset+data.limit < total else None,
        scanned=scanned, complete=error_count == 0, errors=errors, error_count=error_count)


class BinaryContentError(ValueError):
    pass


def decode_file(data):
    path = absolute(data.path)
    if not path.is_file(): raise ValueError('Expected a regular file')
    with path.open('rb') as stream: raw = stream.read(data.max_bytes+1)
    if len(raw) > data.max_bytes: raise ValueError('File exceeds max_bytes')
    encoding = data.encoding
    if encoding == 'auto':
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)): encoding = 'utf-32'
        elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)): encoding = 'utf-16'
        elif raw.startswith(codecs.BOM_UTF8): encoding = 'utf-8-sig'
        else:
            if b'\x00' in raw: raise BinaryContentError('NUL bytes: binary file or text requiring explicit encoding')
            try:
                raw.decode('utf-8')
                encoding = 'utf-8'
            except UnicodeDecodeError:
                match = from_bytes(raw).best()
                if match is None: raise ValueError('Unable to detect encoding; supply encoding explicitly')
                encoding = match.encoding
    return path, raw.decode(encoding, errors='strict'), encoding


def read_text(data):
    path, text, encoding = decode_file(data)
    # Split only LF, CRLF and CR; Unicode line separator characters remain content.
    lines = re.findall(r'[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$', text)
    end = len(lines) if data.count is None else data.offset + data.count
    selected = lines[data.offset:end]
    following = data.offset + len(selected)
    return ReadResult(path=workspace().virtual(path), encoding=encoding, detected=data.encoding == 'auto', text=''.join(selected),
        offset=data.offset, lines_returned=len(selected), total_lines=len(lines),
        next_offset=following if following < len(lines) and selected else None)


def file_format(data):
    if data.format != 'auto': return data.format
    suffix = Path(data.path).suffix.lower()
    formats = {'.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml'}
    if suffix not in formats: raise ValueError('Cannot infer format; specify json, yaml or toml')
    return formats[suffix]


def normalize(value, active=None):
    active = set() if active is None else active
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)): return value.isoformat()
    if value is None or isinstance(value, (str, bool, int)): return value
    if isinstance(value, float):
        import math
        if not math.isfinite(value): raise ValueError('Non-finite numbers are not JSON-compatible')
        return value
    if isinstance(value, (list, dict)):
        if id(value) in active: raise ValueError('Recursive YAML aliases are not supported')
        active.add(id(value))
        try:
            if isinstance(value, list): return [normalize(v, active) for v in value]
            if any(not isinstance(k, str) for k in value): raise ValueError('Mapping keys must be strings')
            return {k: normalize(v, active) for k, v in value.items()}
        finally: active.remove(id(value))
    raise ValueError('Unsupported value type: ' + type(value).__name__)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate mapping key: ' + str(key))
        result[key] = value
    return result

class UniqueSafeLoader(yaml.SafeLoader):
    pass

def yaml_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    return unique_pairs((loader.construct_object(k, deep=deep), loader.construct_object(v, deep=deep)) for k, v in node.value)

UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def read_jyt(data):
    path, text, encoding = decode_file(data)
    fmt = file_format(data)
    if fmt == 'json': value = json.loads(text, object_pairs_hook=unique_pairs)
    elif fmt == 'yaml': value = yaml.load(text, Loader=UniqueSafeLoader)
    else: value = tomllib.loads(text)
    return JytResult(path=workspace().virtual(path), format=fmt, encoding=encoding, data=normalize(value))


def token_tree(tokens):
    root = []
    stack = [root]
    for token in tokens:
        if token.nesting == -1:
            if len(stack) == 1: raise ValueError('Unbalanced Markdown tokens')
            stack.pop()
            continue
        node = {'type': token.type.removesuffix('_open'), 'tag': token.tag, 'content': token.content,
                'attrs': dict(token.attrs), 'lines': token.map, 'info': token.info, 'markup': token.markup}
        if token.children is not None: node['children'] = token_tree(token.children)
        if token.nesting == 1: node['children'] = []
        stack[-1].append(node)
        if token.nesting == 1: stack.append(node['children'])
    return root


def read_markdown(data):
    path, text, encoding = decode_file(data)
    parser = MarkdownIt('commonmark').enable('table').enable('strikethrough')
    return MarkdownResult(path=workspace().virtual(path), encoding=encoding, nodes=token_tree(parser.parse(text)))


def write_bytes(data, payload, operation):
    path = absolute(data.path)
    if path.is_symlink() or (path.exists() and not path.is_file()): raise ValueError('Target must be a regular file, not a symlink')
    if path.exists() and not data.overwrite: raise FileExistsError(str(path))
    if data.create_parents: path.parent.mkdir(parents=True, exist_ok=True)
    old_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.fs-twylt-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if old_mode is not None: os.chmod(temporary, old_mode)
        if data.overwrite: os.replace(temporary, path)
        else: os.link(temporary, path)  # Atomic no-clobber publication.
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)
    return MutationResult(operation=operation, path=workspace().virtual(path), changed=True, bytes_written=len(payload))


def write_text(data):
    return write_bytes(data, data.content.encode(data.encoding, errors='strict'), 'write')


def write_jyt(data):
    value = normalize(data.data)
    fmt = file_format(data)
    if fmt == 'json': text = json.dumps(value, ensure_ascii=False, indent=data.indent, allow_nan=False) + '\n'
    elif fmt == 'yaml': text = yaml.safe_dump(value, allow_unicode=True, sort_keys=False, indent=data.indent)
    else:
        if not isinstance(value, dict): raise ValueError('TOML root must be an object')
        text = tomli_w.dumps(value)
    return write_bytes(data, text.encode(data.encoding, errors='strict'), 'write_jyt')


def transfer(data, operation):
    source, destination = absolute(data.source), absolute(data.destination)
    workspace().protect_root(destination)
    if operation == 'move': workspace().protect_root(source)
    workspace().tree(source)
    if not os.path.lexists(source): raise FileNotFoundError(str(source))
    src_kind = kind(source.lstat().st_mode)
    if src_kind == 'other': raise ValueError('Special files are not supported')
    if source == destination or (source.exists() and destination.exists() and os.path.samefile(source, destination)):
        raise ValueError('Source and destination are the same object')
    resolved_source, resolved_dest = source.resolve(), destination.resolve()
    if src_kind == 'directory' and (resolved_dest == resolved_source or resolved_source in resolved_dest.parents):
        raise ValueError('Destination cannot be inside source directory')
    if os.path.lexists(destination):
        if not data.overwrite: raise FileExistsError(str(destination))
        if destination.is_symlink() or not destination.is_file() or src_kind == 'directory':
            raise ValueError('Only an existing regular file may be overwritten by a file or link')
    if data.create_parents: destination.parent.mkdir(parents=True, exist_ok=True)
    if operation == 'move':
        shutil.move(str(source), str(destination))
    elif src_kind == 'directory':
        shutil.copytree(source, destination, symlinks=True)
    elif src_kind == 'symlink':
        if destination.exists(): raise ValueError('Copying a symlink requires an absent destination')
        os.symlink(os.readlink(source), destination, target_is_directory=source.is_dir())
    else:
        fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix='.fs-twylt-')
        os.close(fd)
        try:
            shutil.copy2(source, temporary)
            if data.overwrite: os.replace(temporary, destination)
            else: os.link(temporary, destination)
        finally:
            if os.path.lexists(temporary): os.unlink(temporary)
    return MutationResult(operation=operation, path=workspace().virtual(destination), source=workspace().virtual(source), changed=True)


def delete(data):
    path = absolute(data.path)
    workspace().protect_root(path)
    workspace().tree(path)
    if not os.path.lexists(path):
        if not data.missing_ok: raise FileNotFoundError(str(path))
        return MutationResult(operation='delete', path=workspace().virtual(path), changed=False)
    if not path.is_symlink():
        resolved, cwd = path.resolve(), Path.cwd().resolve()
        if resolved.parent == resolved or resolved == cwd or resolved in cwd.parents:
            raise ValueError('Refusing deletion of filesystem root, cwd, or an ancestor of cwd')
    if path.is_dir() and not path.is_symlink():
        if not data.recursive:
            with os.scandir(path) as iterator:
                if next(iterator, None) is not None: raise ValueError('Non-empty directory requires recursive=true')
        if not data.dry_run:
            if data.recursive: shutil.rmtree(path)
            else: path.rmdir()
    elif not data.dry_run: path.unlink()
    return MutationResult(operation='delete', path=workspace().virtual(path), changed=not data.dry_run)


# Small explicit signature set: positive binary evidence, not a MIME database.
_BINARY_SIGNATURES = (b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'GIF87a', b'GIF89a',
                      b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x7fELF',
                      b'\x1f\x8b', b'%PDF-', b'\x00asm')

def inspect_file(data):
    path = absolute(data.path)
    if data.encoding != 'auto': codecs.lookup(data.encoding)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode): raise ValueError('fs_stat requires a regular file')
    def result(content_type, reason, **kwargs):
        return FileStats(size_bytes=before.st_size, content_type=content_type, reason=reason, **kwargs)
    if before.st_size > data.max_bytes:
        return result('unknown', 'size_limit')
    with path.open('rb') as stream:
        raw = stream.read(data.max_bytes + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        return result('unknown', 'file_changed')
    if len(raw) > data.max_bytes: return result('unknown', 'size_limit')
    if len(raw) != before.st_size: return result('unknown', 'file_changed')
    if raw.startswith(_BINARY_SIGNATURES): return result('binary', 'binary_signature')
    encoding = data.encoding
    encoding_source = 'explicit'
    if encoding == 'auto':
        encoding_source = 'bom'
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)): encoding = 'utf-32'
        elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)): encoding = 'utf-16'
        elif raw.startswith(codecs.BOM_UTF8): encoding = 'utf-8-sig'
        else:
            if b'\x00' in raw or re.search(rb'[\x01-\x08\x0b\x0e-\x1f\x7f]', raw):
                return result('binary', 'binary_controls')
            encoding = 'utf-8'
            encoding_source = 'utf8'
    try: text = raw.decode(encoding, errors='strict')
    except UnicodeError: return result('unknown', 'undecodable')
    if re.search(r'[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]', text):
        return result('binary', 'binary_controls')
    lines = sum(1 for _ in re.finditer(r'\r\n|\r|\n', text))
    if text and not text.endswith(('\r', '\n')): lines += 1
    endings = set(re.findall(r'\r\n|\r|\n', text))
    newline_names = {'\r\n': 'crlf', '\n': 'lf', '\r': 'cr'}
    line_ending = 'none' if not endings else newline_names[next(iter(endings))] if len(endings) == 1 else 'mixed'
    indent_chars = set()
    for line in re.split(r'\r\n|\r|\n', text):
        if not line.strip(): continue
        leading = re.match(r'[ \t]*', line).group()
        indent_chars.update(leading)
    indentation = 'mixed' if len(indent_chars) == 2 else 'space' if ' ' in indent_chars else 'tab' if '\t' in indent_chars else 'none'
    return result('text', 'decoded_text', encoding=encoding, line_count=lines,
                  encoding_source=encoding_source, line_ending=line_ending, indentation=indentation)


def file_stat(data):
    stats = inspect_file(data)
    return StatResult(path=workspace().virtual(absolute(data.path)), **stats.model_dump())


def chmod(data):
    path = absolute(data.path)
    workspace().protect_root(path)
    if os.name != 'posix': raise ValueError('fs_chmod requires POSIX; Windows permission semantics are not emulated')
    before = stat.S_IMODE(path.stat().st_mode)
    wanted = int(data.mode, 8)
    if not data.dry_run and before != wanted:
        workspace().inspect(path)
        os.chmod(path, wanted)
    actual = stat.S_IMODE(path.stat().st_mode)
    return ChmodResult(path=workspace().virtual(path), previous_mode=format(before, '04o'),
                       requested_mode=format(wanted, '04o'), mode=format(actual, '04o'),
                       changed=actual != before, dry_run=data.dry_run)

class Input(SearchInput):
    pass

class FilesystemTool(WorkspaceTransport, Tool[Input, SearchResult]):
    input_model = Input
    output_model = SearchResult
    name = 'fs_list'
    version = '0.5.0'
    description = 'List directory entries with bounded depth, filters and pagination.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt==1.0.0\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': '.', 'max_depth': 1, 'limit': 100}, 'output': {'entries': [], 'total': 0, 'offset': 0, 'limit': 100, 'next_offset': None, 'scanned': 0, 'complete': True, 'errors': [], 'error_count': 0}}]
    input_schema_name = 'fs_list.input'
    input_schema_version = '2.1.0'
    output_schema_name = 'fs_list.output'
    output_schema_version = '2.2.0'

    def biz(self, data):
        with Workspace(self.name):
            return search(data)

if __name__ == '__main__':
    FilesystemTool.run()
