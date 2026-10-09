from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from pydantic import Field
from twylt import Tool, Requirements
from twylt.guardrails import Workspace
from filesystem_common.common import RecursiveInput, SearchResult, search

class GlobInput(RecursiveInput):
    pattern: str = Field(min_length=1, description='Relative POSIX glob: *, ?, [], and ** as an entire segment. ** matches zero or more segments.')

class Input(GlobInput):
    pass

class FilesystemTool(Tool[Input, SearchResult]):
    input_model = Input
    output_model = SearchResult
    name = 'fs_glob'
    version = '0.6.0'
    description = 'Search relative paths using a POSIX glob and shared metadata filters.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': '.', 'pattern': '**/*.py', 'type': 'file', 'limit': 100}, 'output': {'entries': [], 'total': 0, 'offset': 0, 'limit': 100, 'next_offset': None, 'scanned': 0, 'complete': True, 'errors': [], 'error_count': 0}}]
    input_schema_name = 'fs_glob.input'
    input_schema_version = '2.1.0'
    output_schema_name = 'fs_glob.output'
    output_schema_version = '2.2.0'

    def biz(self, data):
        with Workspace(self.name):
            return search(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
