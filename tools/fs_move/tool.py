from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from twylt import Tool, Requirements
from twylt.guardrails import Workspace
from filesystem_common.common import MutationResult, TransferInput, transfer

class Input(TransferInput):
    pass

class FilesystemTool(Tool[Input, MutationResult]):
    input_model = Input
    output_model = MutationResult
    name = 'fs_move'
    version = '0.6.0'
    description = 'Move a file, directory tree to an exact destination.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'source': 'example.txt', 'destination': 'example-moved.txt'}, 'output': {'operation': 'move', 'path': '/example-moved.txt', 'source': '/example.txt', 'changed': True, 'bytes_written': None}}]
    input_schema_name = 'fs_move.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_move.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return transfer(data, 'move')
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
