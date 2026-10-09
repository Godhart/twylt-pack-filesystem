from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from twylt import Tool, Requirements
from twylt.guardrails import Workspace
from filesystem_common.common import SearchInput, SearchResult, search

class Input(SearchInput):
    pass

class FilesystemTool(Tool[Input, SearchResult]):
    input_model = Input
    output_model = SearchResult
    name = 'fs_list'
    version = '0.6.0'
    description = 'List directory entries with bounded depth, filters and pagination.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': '.', 'max_depth': 1, 'limit': 100}, 'output': {'entries': [], 'total': 0, 'offset': 0, 'limit': 100, 'next_offset': None, 'scanned': 0, 'complete': True, 'errors': [], 'error_count': 0}}]
    input_schema_name = 'fs_list.input'
    input_schema_version = '2.1.0'
    output_schema_name = 'fs_list.output'
    output_schema_version = '2.2.0'

    def biz(self, data):
        with Workspace(self.name):
            return search(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
