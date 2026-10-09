# Testing filesystem 0.6.0

Python 3.12, TWYLT 1.1.1, 2026-10-08: 198 passed. No external network used.
All earlier behavioral scenarios are preserved. Policy tests now use TWYLT itself;
assertions were updated for code 6 and the centralized transport incident code.
Copied source packs are scanned by builder 0.4.1 and their actual generated
launcher runs in a nested cwd outside workspace using file transport.
Filesystem and Git exercise real operations; Docker tests use mock daemon APIs.
No pack Python distribution is installed. Whole tools/shared tree is required.

Base: https://github.com/Godhart/twylt-pack-filesystem, commit fa5daa98ed7dd066ea1e497b41132580a31b9c1e.
Archive includes a patch against this fresh GitHub checkout and SHA256SUMS.

```bash
python -m pip install -r requirements.txt
# Integration tests also need toolpack-builder 0.4.1.
python -m pytest -q tests
python scripts/export_schemas.py
```

## Previous release results (historical)

# Release validation — filesystem-twylt-pack-0.5.0

2026-10-02, Linux, Python 3.12, TWYLT 1.0.0, Pydantic 2.13.5.
`python -m pytest -q`: **197 passed** (178 prior cases preserved; 19 new).

New cases cover LF/CRLF/CR/mixed/none, spaces/tabs/mixed/none, blank lines,
internal versus leading whitespace, UTF-8/16/32 BOM provenance, explicit codecs,
non-text null fields and identical enriched stats in list/find/glob.
Existing file access, chmod, content search, transport and audit tests pass.
Shared workspace policy is unchanged. No external services used.
Windows/macOS and ToolHub GUI import were not tested. The prior classification,
regex and workspace isolation limitations remain documented in README/WORKSPACE.
