from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
import json
from typing import Literal
from pydantic import Field, JsonValue
from twylt import Tool, Requirements
import yaml
import tomli_w
from twylt.guardrails import Workspace
from filesystem_common.common import MutationResult, PathInput, file_format, normalize, write_bytes

class WriteJytInput(PathInput):
    data: JsonValue = Field(description='JSON-compatible structure; TOML requires an object and cannot represent null.')
    format: Literal['auto', 'json', 'yaml', 'toml'] = Field(default='auto', description='auto infers format from extension.')
    encoding: str = Field(default='utf-8', description='Explicit Python codec; use UTF-8 for interoperable JSON/YAML/TOML.')
    overwrite: bool = Field(default=False, description='Explicitly allow replacing an existing regular file.')
    create_parents: bool = Field(default=False, description='Create missing parent directories.')
    indent: int = Field(default=2, ge=1, le=8, description='Indentation for JSON/YAML; TOML writer controls its own layout.')

def write_jyt(data):
    value = normalize(data.data)
    fmt = file_format(data)
    if fmt == 'json':
        text = json.dumps(value, ensure_ascii=False, indent=data.indent, allow_nan=False) + '\n'
    elif fmt == 'yaml':
        text = yaml.safe_dump(value, allow_unicode=True, sort_keys=False, indent=data.indent)
    else:
        if not isinstance(value, dict):
            raise ValueError('TOML root must be an object')
        text = tomli_w.dumps(value)
    return write_bytes(data, text.encode(data.encoding, errors='strict'), 'write_jyt')

class Input(WriteJytInput):
    pass

class FilesystemTool(Tool[Input, MutationResult]):
    input_model = Input
    output_model = MutationResult
    name = 'fs_write_jyt'
    version = '0.6.0'
    description = 'Serialize a JSON-compatible structure as JSON, YAML or TOML.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'settings.toml', 'data': {'enabled': True, 'name': 'demo'}}, 'output': {'operation': 'write_jyt', 'path': '/settings.toml', 'source': None, 'changed': True, 'bytes_written': None}}]
    input_schema_name = 'fs_write_jyt.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_write_jyt.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return write_jyt(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
