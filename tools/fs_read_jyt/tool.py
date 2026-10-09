from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
import json
import tomllib
from typing import Literal
from pydantic import Field, JsonValue
from twylt import Tool, Requirements
import yaml
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import Model, ReadBase, decode_file, file_format, normalize

class JytInput(ReadBase):
    format: Literal['auto', 'json', 'yaml', 'toml'] = Field(default='auto', description='auto uses the filename extension .json/.yaml/.yml/.toml.')

class JytResult(Model):
    path: str
    format: str
    encoding: str
    data: JsonValue

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate mapping key: ' + str(key))
        result[key] = value
    return result

class UniqueSafeLoader(yaml.SafeLoader):
    pass

def yaml_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    return unique_pairs(((loader.construct_object(k, deep=deep), loader.construct_object(v, deep=deep)) for k, v in node.value))
UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)

def read_jyt(data):
    path, text, encoding = decode_file(data)
    fmt = file_format(data)
    if fmt == 'json':
        value = json.loads(text, object_pairs_hook=unique_pairs)
    elif fmt == 'yaml':
        value = yaml.load(text, Loader=UniqueSafeLoader)
    else:
        value = tomllib.loads(text)
    return JytResult(path=workspace().virtual(path), format=fmt, encoding=encoding, data=normalize(value))

class Input(JytInput):
    pass

class FilesystemTool(Tool[Input, JytResult]):
    input_model = Input
    output_model = JytResult
    name = 'fs_read_jyt'
    version = '0.6.0'
    description = 'Read JSON, YAML or TOML into a JSON-compatible data structure.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'settings.yaml'}, 'output': {'path': '/settings.yaml', 'format': 'yaml', 'encoding': 'utf-8', 'data': {'enabled': True}}}]
    input_schema_name = 'fs_read_jyt.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_read_jyt.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return read_jyt(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
