"""Generate standalone TWYLT tools, examples and machine-readable pack manifest."""
from pathlib import Path
import json

BASE = Path(__file__).resolve().parents[1]
POLICY = (BASE / 'src/workspace.py').read_text(encoding='utf-8')
COMMON = (BASE / 'src/common.py').read_text(encoding='utf-8').replace('from workspace import Workspace, WorkspaceDenied, WorkspaceTransport, workspace', POLICY)
REQUIREMENTS = (BASE / 'requirements.txt').read_text(encoding='utf-8')
SPECS = {
    'stat': ('StatInput', 'StatResult', 'file_stat(data)', 'Report file bytes, text/binary/unknown classification and exact text line count.', {'path':'example.txt'}),
    'chmod': ('ChmodInput', 'ChmodResult', 'chmod(data)', 'Set exact POSIX permissions on one workspace file or directory.', {'path':'example.txt','mode':'0644'}),
    'list': ('SearchInput', 'SearchResult', 'search(data)', 'List directory entries with bounded depth, filters and pagination.', {'path':'.', 'max_depth':1, 'limit':100}),
    'glob': ('GlobInput', 'SearchResult', 'search(data)', 'Search relative paths using a POSIX glob and shared metadata filters.', {'path':'.', 'pattern':'**/*.py', 'type':'file', 'limit':100}),
    'find': ('FindInput', 'SearchResult', 'search(data)', 'Find objects recursively by metadata and optional full-text content filter.', {'path':'.', 'name_regex':r'\.py$', 'type':'file', 'max_depth':3, 'content':{'query':'TODO','ignore_case':True}}),
    'read': ('ReadInput', 'ReadResult', 'read_text(data)', 'Read a line slice with explicit encoding or heuristic detection.', {'path':'example.txt', 'encoding':'auto', 'offset':0, 'count':100}),
    'read_jyt': ('JytInput', 'JytResult', 'read_jyt(data)', 'Read JSON, YAML or TOML into a JSON-compatible data structure.', {'path':'settings.yaml'}),
    'read_markdown': ('MarkdownInput', 'MarkdownResult', 'read_markdown(data)', 'Parse CommonMark plus tables and strikethrough into a nested token AST.', {'path':'README.md'}),
    'write': ('WriteInput', 'MutationResult', 'write_text(data)', 'Create or explicitly replace a text file.', {'path':'example.txt', 'content':'Hello\n'}),
    'write_jyt': ('WriteJytInput', 'MutationResult', 'write_jyt(data)', 'Serialize a JSON-compatible structure as JSON, YAML or TOML.', {'path':'settings.toml', 'data':{'enabled':True, 'name':'demo'}}),
    'copy': ('TransferInput', 'MutationResult', "transfer(data, 'copy')", 'Copy a file, directory tree to an exact destination.', {'source':'example.txt', 'destination':'example-copy.txt'}),
    'move': ('TransferInput', 'MutationResult', "transfer(data, 'move')", 'Move a file, directory tree to an exact destination.', {'source':'example.txt', 'destination':'example-moved.txt'}),
    'delete': ('DeleteInput', 'MutationResult', 'delete(data)', 'Remove a file or directory, requiring explicit recursive deletion.', {'path':'example-copy.txt', 'dry_run':True}),
}

def example_output(op):
    if op == 'stat': return {'path':'/example.txt','size_bytes':6,'content_type':'text','line_count':1,'encoding':'utf-8','encoding_source':'utf8','line_ending':'lf','indentation':'none','reason':'decoded_text'}
    if op == 'chmod': return {'path':'/example.txt','previous_mode':'0600','requested_mode':'0644','mode':'0644','changed':True,'dry_run':False}
    if op in ('list', 'glob', 'find'):
        return {'entries':[], 'total':0, 'offset':0, 'limit':100, 'next_offset':None, 'scanned':0, 'complete':True, 'errors':[], 'error_count':0}
    if op == 'read': return {'path':'/example.txt', 'encoding':'utf-8', 'detected':True, 'text':'Hello\n', 'offset':0, 'lines_returned':1, 'total_lines':1, 'next_offset':None}
    if op == 'read_jyt': return {'path':'/settings.yaml', 'format':'yaml', 'encoding':'utf-8', 'data':{'enabled':True}}
    if op == 'read_markdown': return {'path':'/README.md', 'encoding':'utf-8', 'nodes':[]}
    example = SPECS[op][4]
    return {'operation':op, 'path':'/'+example.get('path', example.get('destination','')), 'source':'/'+example['source'] if 'source' in example else None, 'changed':op != 'delete', 'bytes_written':6 if op == 'write' else None}

manifest = {'name':'filesystem-twylt-pack', 'version':'0.5.0', 'protocol':'TWYLT 1', 'tools':[]}
for op, (input_type, output_type, call, description, example) in SPECS.items():
    folder = BASE / 'tools' / ('fs_'+op)
    folder.mkdir(parents=True, exist_ok=True)
    code = COMMON + f'''
class Input({input_type}):
    pass

class FilesystemTool(WorkspaceTransport, Tool[Input, {output_type}]):
    input_model = Input
    output_model = {output_type}
    name = 'fs_{op}'
    version = '0.5.0'
    description = {description!r}
    requirements = Requirements(tool='pip', format='requirements.txt', content={REQUIREMENTS!r})
    few_shots = {[{'input':example, 'output':example_output(op)}]!r}
    input_schema_name = 'fs_{op}.input'
    input_schema_version = {'1.0.0' if op in ('stat','chmod') else '2.2.0' if op == 'find' else '2.1.0' if op in ('list','glob') else '2.0.0'!r}
    output_schema_name = 'fs_{op}.output'
    output_schema_version = {'1.1.0' if op == 'stat' else '1.0.0' if op == 'chmod' else '2.2.0' if op in ('list','find','glob') else '2.0.0'!r}

    def biz(self, data):
        with Workspace(self.name):
            return {call}

if __name__ == '__main__':
    FilesystemTool.run()
'''
    (folder/'tool.py').write_text(code, encoding='utf-8')
    (folder/'run.py').write_text('from pathlib import Path\nfrom twylt.bootstrap import run_tool_file\n\nif __name__ == "__main__":\n    run_tool_file(Path(__file__).with_name("tool.py"))\n', encoding='utf-8')
    (folder/'example.json').write_text(json.dumps(example, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    manifest['tools'].append({'name':'fs_'+op, 'entrypoint':f'tools/fs_{op}/tool.py', 'bootstrap':f'tools/fs_{op}/run.py', 'description':description})
(BASE/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
