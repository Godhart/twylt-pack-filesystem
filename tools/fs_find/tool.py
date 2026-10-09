from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from pydantic import Field, model_validator
from twylt import Tool, Requirements
from twylt.guardrails import Workspace
from filesystem_common.common import Model, RecursiveInput, SearchResult, search

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

class Input(FindInput):
    pass

class FilesystemTool(Tool[Input, SearchResult]):
    input_model = Input
    output_model = SearchResult
    name = 'fs_find'
    version = '0.6.0'
    description = 'Find objects recursively by metadata and optional full-text content filter.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': '.', 'name_regex': '\\.py$', 'type': 'file', 'max_depth': 3, 'content': {'query': 'TODO', 'ignore_case': True}}, 'output': {'entries': [], 'total': 0, 'offset': 0, 'limit': 100, 'next_offset': None, 'scanned': 0, 'complete': True, 'errors': [], 'error_count': 0}}]
    input_schema_name = 'fs_find.input'
    input_schema_version = '2.2.0'
    output_schema_name = 'fs_find.output'
    output_schema_version = '2.2.0'

    def biz(self, data):
        with Workspace(self.name):
            return search(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
