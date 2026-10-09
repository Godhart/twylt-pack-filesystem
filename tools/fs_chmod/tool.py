from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
import os
import stat
from pydantic import Field
from twylt import Tool, Requirements
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import Model, PathInput, absolute

class ChmodInput(PathInput):
    mode: str = Field(pattern='^[0-7]{3,4}$', description='Exact POSIX octal mode, e.g. 644, 0755 or 0640; no symbolic or recursive mode.')
    dry_run: bool = Field(default=False, description='Report requested mode without applying it.')

class ChmodResult(Model):
    path: str
    previous_mode: str
    requested_mode: str
    mode: str = Field(description='Actual current mode after operation, or original mode for dry_run.')
    changed: bool
    dry_run: bool

def chmod(data):
    path = absolute(data.path)
    workspace().protect_root(path)
    if os.name != 'posix':
        raise ValueError('fs_chmod requires POSIX; Windows permission semantics are not emulated')
    before = stat.S_IMODE(path.stat().st_mode)
    wanted = int(data.mode, 8)
    if not data.dry_run and before != wanted:
        workspace().inspect(path)
        os.chmod(path, wanted)
    actual = stat.S_IMODE(path.stat().st_mode)
    return ChmodResult(path=workspace().virtual(path), previous_mode=format(before, '04o'), requested_mode=format(wanted, '04o'), mode=format(actual, '04o'), changed=actual != before, dry_run=data.dry_run)

class Input(ChmodInput):
    pass

class FilesystemTool(Tool[Input, ChmodResult]):
    input_model = Input
    output_model = ChmodResult
    name = 'fs_chmod'
    version = '0.6.0'
    description = 'Set exact POSIX permissions on one workspace file or directory.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'example.txt', 'mode': '0644'}, 'output': {'path': '/example.txt', 'previous_mode': '0600', 'requested_mode': '0644', 'mode': '0644', 'changed': True, 'dry_run': False}}]
    input_schema_name = 'fs_chmod.input'
    input_schema_version = '1.0.0'
    output_schema_name = 'fs_chmod.output'
    output_schema_version = '1.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return chmod(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
