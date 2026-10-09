from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
import os
import shutil
from pathlib import Path
from pydantic import Field
from twylt import Tool, Requirements
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import MutationResult, PathInput, absolute

class DeleteInput(PathInput):
    recursive: bool = Field(default=False, description='Required for non-empty directories; symlinks and workspace root are refused.')
    missing_ok: bool = Field(default=False, description='Succeed if the path does not exist.')
    dry_run: bool = Field(default=False, description='Validate and report the target without removing it.')

def delete(data):
    path = absolute(data.path)
    workspace().protect_root(path)
    workspace().tree(path)
    if not os.path.lexists(path):
        if not data.missing_ok:
            raise FileNotFoundError(str(path))
        return MutationResult(operation='delete', path=workspace().virtual(path), changed=False)
    if not path.is_symlink():
        resolved, cwd = (path.resolve(), Path.cwd().resolve())
        if resolved.parent == resolved or resolved == cwd or resolved in cwd.parents:
            raise ValueError('Refusing deletion of filesystem root, cwd, or an ancestor of cwd')
    if path.is_dir() and (not path.is_symlink()):
        if not data.recursive:
            with os.scandir(path) as iterator:
                if next(iterator, None) is not None:
                    raise ValueError('Non-empty directory requires recursive=true')
        if not data.dry_run:
            if data.recursive:
                shutil.rmtree(path)
            else:
                path.rmdir()
    elif not data.dry_run:
        path.unlink()
    return MutationResult(operation='delete', path=workspace().virtual(path), changed=not data.dry_run)

class Input(DeleteInput):
    pass

class FilesystemTool(Tool[Input, MutationResult]):
    input_model = Input
    output_model = MutationResult
    name = 'fs_delete'
    version = '0.6.0'
    description = 'Remove a file or directory, requiring explicit recursive deletion.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'example-copy.txt', 'dry_run': True}, 'output': {'operation': 'delete', 'path': '/example-copy.txt', 'source': None, 'changed': False, 'bytes_written': None}}]
    input_schema_name = 'fs_delete.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_delete.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return delete(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
