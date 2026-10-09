from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from pydantic import Field
from twylt import Tool, Requirements
from twylt.guardrails import Workspace
from filesystem_common.common import MutationResult, PathInput, write_bytes

class WriteInput(PathInput):
    content: str = Field(description='Complete text to write, without implicit newline changes.')
    encoding: str = Field(default='utf-8', description='Explicit Python codec; auto is not supported for writing.')
    overwrite: bool = Field(default=False, description='Allow atomic replacement of an existing regular file.')
    create_parents: bool = Field(default=False, description='Create missing parent directories.')

def write_text(data):
    return write_bytes(data, data.content.encode(data.encoding, errors='strict'), 'write')

class Input(WriteInput):
    pass

class FilesystemTool(Tool[Input, MutationResult]):
    input_model = Input
    output_model = MutationResult
    name = 'fs_write'
    version = '0.6.0'
    description = 'Create or explicitly replace a text file.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'example.txt', 'content': 'Hello\n'}, 'output': {'operation': 'write', 'path': '/example.txt', 'source': None, 'changed': True, 'bytes_written': 6}}]
    input_schema_name = 'fs_write.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_write.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return write_text(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
