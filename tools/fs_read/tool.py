from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
import re
from pydantic import Field
from twylt import Tool, Requirements
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import Model, ReadBase, decode_file

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

def read_text(data):
    path, text, encoding = decode_file(data)
    lines = re.findall('[^\\r\\n]*(?:\\r\\n|\\r|\\n)|[^\\r\\n]+$', text)
    end = len(lines) if data.count is None else data.offset + data.count
    selected = lines[data.offset:end]
    following = data.offset + len(selected)
    return ReadResult(path=workspace().virtual(path), encoding=encoding, detected=data.encoding == 'auto', text=''.join(selected), offset=data.offset, lines_returned=len(selected), total_lines=len(lines), next_offset=following if following < len(lines) and selected else None)

class Input(ReadInput):
    pass

class FilesystemTool(Tool[Input, ReadResult]):
    input_model = Input
    output_model = ReadResult
    name = 'fs_read'
    version = '0.6.0'
    description = 'Read a line slice with explicit encoding or heuristic detection.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'example.txt', 'encoding': 'auto', 'offset': 0, 'count': 100}, 'output': {'path': '/example.txt', 'encoding': 'utf-8', 'detected': True, 'text': 'Hello\n', 'offset': 0, 'lines_returned': 1, 'total_lines': 1, 'next_offset': None}}]
    input_schema_name = 'fs_read.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_read.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return read_text(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
