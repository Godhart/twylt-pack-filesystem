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
