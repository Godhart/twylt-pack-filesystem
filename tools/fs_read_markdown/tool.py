from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'shared'))
from pydantic import Field, JsonValue
from twylt import Tool, Requirements
from markdown_it import MarkdownIt
from twylt.guardrails import Workspace, workspace
from filesystem_common.common import Model, ReadBase, decode_file

class MarkdownInput(ReadBase):
    pass

class MarkdownResult(Model):
    path: str
    encoding: str
    nodes: list[dict[str, JsonValue]] = Field(description='Nested markdown-it token AST; source line ranges are zero-based, end-exclusive.')

def token_tree(tokens):
    root = []
    stack = [root]
    for token in tokens:
        if token.nesting == -1:
            if len(stack) == 1:
                raise ValueError('Unbalanced Markdown tokens')
            stack.pop()
            continue
        node = {'type': token.type.removesuffix('_open'), 'tag': token.tag, 'content': token.content, 'attrs': dict(token.attrs), 'lines': token.map, 'info': token.info, 'markup': token.markup}
        if token.children is not None:
            node['children'] = token_tree(token.children)
        if token.nesting == 1:
            node['children'] = []
        stack[-1].append(node)
        if token.nesting == 1:
            stack.append(node['children'])
    return root

def read_markdown(data):
    path, text, encoding = decode_file(data)
    parser = MarkdownIt('commonmark').enable('table').enable('strikethrough')
    return MarkdownResult(path=workspace().virtual(path), encoding=encoding, nodes=token_tree(parser.parse(text)))

class Input(MarkdownInput):
    pass

class FilesystemTool(Tool[Input, MarkdownResult]):
    input_model = Input
    output_model = MarkdownResult
    name = 'fs_read_markdown'
    version = '0.6.0'
    description = 'Parse CommonMark plus tables and strikethrough into a nested token AST.'
    requirements = Requirements(tool='pip', format='requirements.txt', content='twylt>=1.1.1,<2\npydantic>=2,<3\nPyYAML>=6,<7\ntomli-w>=1,<2\nmarkdown-it-py>=3,<5\ncharset-normalizer>=3,<4\n')
    few_shots = [{'input': {'path': 'README.md'}, 'output': {'path': '/README.md', 'encoding': 'utf-8', 'nodes': []}}]
    input_schema_name = 'fs_read_markdown.input'
    input_schema_version = '2.0.0'
    output_schema_name = 'fs_read_markdown.output'
    output_schema_version = '2.0.0'

    def biz(self, data):
        with Workspace(self.name):
            return read_markdown(data)
TOOL = FilesystemTool
if __name__ == '__main__':
    FilesystemTool.run()
