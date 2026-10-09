from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from twylt import Tool, Requirements
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import FileStats, StatInput, absolute, inspect_file

class StatResult(FileStats):
    path: str

def file_stat(data):
    stats = inspect_file(data)
    return StatResult(path=workspace().virtual(absolute(data.path)), **stats.model_dump())

class Input(StatInput):
    pass

class FilesystemTool(Tool[Input, StatResult]):
    input_model = Input
    output_model = StatResult
    name = 'fs_stat'
    version = '0.6.0'
    description = 'Report file bytes, text/binary/unknown classification and exact text line count.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'example.txt'}, 'output': {'path': '/example.txt', 'size_bytes': 6, 'content_type': 'text', 'line_count': 1, 'encoding': 'utf-8', 'encoding_source': 'utf8', 'line_ending': 'lf', 'indentation': 'none', 'reason': 'decoded_text'}}]
    input_schema_name = 'fs_stat.input'
    input_schema_version = '1.0.0'
    output_schema_name = 'fs_stat.output'
    output_schema_version = '1.1.0'

    def biz(self, data):
        with Workspace(self.name):
            return file_stat(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
