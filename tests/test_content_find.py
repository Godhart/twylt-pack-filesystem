import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'tests/legacy'))
import common as fs

@pytest.fixture
def root(tmp_path,monkeypatch):
    root=tmp_path/'ws';root.mkdir()
    monkeypatch.setenv('TWYLT_WORKSPACE_ROOT',str(root))
    monkeypatch.setenv('TWYLT_INCIDENT_LOG',str(tmp_path/'incidents.jsonl'))
    return root

def find(**kwargs):
    return fs.search(fs.FindInput(path='/',**kwargs))

def test_literal_and_metadata_pagination(root):
    (root/'a.txt').write_text('TODO TODO')
    (root/'b.txt').write_text('todo')
    (root/'c.py').write_text('TODO')
    (root/'sub').mkdir();(root/'sub/d.txt').write_text('nothing')
    r=find(content=fs.ContentFilter(query='TODO'),name_regex=r'\.txt$',limit=1)
    assert [e.path for e in r.entries]==['/a.txt'] and r.total==1
    r=find(content=fs.ContentFilter(query='todo',ignore_case=True),limit=1)
    assert r.total==3 and r.next_offset==1 and r.complete
    page=find(content=fs.ContentFilter(query='todo',ignore_case=True),offset=1,limit=1)
    assert [e.path for e in page.entries]==['/b.txt'] and page.total==3
    assert find(content=fs.ContentFilter(query='absent')).total==0
    assert find().total==5  # Existing directory and metadata search behavior preserved.

@pytest.mark.parametrize('query,regex,expected', [('a.b',False,1),('a.b',True,2),('(?m)^todo$',True,1),('(?s)start.*end',True,1),('start\nend',False,1)])
def test_regex_literal_and_multiline(root,query,regex,expected):
    (root/'one').write_text('a.b\ntodo\nstart\nend')
    (root/'two').write_text('axb')
    assert find(content=fs.ContentFilter(query=query,regex=regex)).total==expected

@pytest.mark.parametrize('encoding,query', [('utf-8','ПРИВЕТ'),('utf-16','ПРИВЕТ'),('utf-32','ПРИВЕТ'),('cp1251','ПРИВЕТ')])
def test_encodings(root,encoding,query):
    (root/'file').write_bytes('Привет мир'.encode(encoding))
    assert find(content=fs.ContentFilter(query=query,encoding=encoding,ignore_case=True)).total==1
    if encoding!='cp1251': assert find(content=fs.ContentFilter(query=query,ignore_case=True)).total==1

def test_binary_policy_and_size_errors(root):
    (root/'binary').write_bytes(b'TODO\0binary')
    assert find(content=fs.ContentFilter(query='TODO')).total==0
    assert find(content=fs.ContentFilter(query='TODO')).complete
    with pytest.raises(fs.BinaryContentError): find(content=fs.ContentFilter(query='TODO',skip_binary=False))
    r=find(content=fs.ContentFilter(query='TODO',skip_binary=False),on_error='skip')
    assert not r.complete and r.error_count==1 and r.errors[0].path=='/binary'
    (root/'binary').unlink();(root/'big').write_text('TODO long file')
    with pytest.raises(ValueError,match='max_bytes'): find(content=fs.ContentFilter(query='TODO',max_bytes=4))
    r=find(content=fs.ContentFilter(query='TODO',max_bytes=4),on_error='skip')
    assert not r.complete and r.error_count==1 and r.total==0

def test_invalid_codec_and_regex_fail_even_on_empty_tree(root):
    with pytest.raises(LookupError): find(content=fs.ContentFilter(query='x',encoding='not-a-codec'),on_error='skip')
    with pytest.raises(fs.re.error): find(content=fs.ContentFilter(query='[',regex=True),on_error='skip')

def test_decode_error_and_metadata_before_content(root):
    (root/'skip.bin').write_bytes(b'\xff\xff')
    (root/'text.txt').write_text('hello')
    assert find(content=fs.ContentFilter(query='hello',encoding='utf-8'),name_regex=r'\.txt$').total==1
    with pytest.raises(UnicodeDecodeError): find(content=fs.ContentFilter(query='hello',encoding='utf-8'))
    r=find(content=fs.ContentFilter(query='hello',encoding='utf-8'),on_error='skip')
    assert r.total==1 and not r.complete and r.error_count==1

def test_no_symlink_follow_and_policy_not_swallowed(root,tmp_path,monkeypatch):
    (tmp_path/'outside').write_text('SECRET')
    (root/'link').symlink_to(tmp_path/'outside')
    assert find(content=fs.ContentFilter(query='SECRET'),on_error='skip').total==0
    (root/'file').write_text('text')
    original=fs.decode_file
    def replaced(data):
        # Simulate replacement between directory metadata and the file-open check.
        (root/'file').unlink();(root/'file').symlink_to(tmp_path/'outside')
        return original(data)
    monkeypatch.setattr(fs,'decode_file',replaced)
    with pytest.raises(fs.WorkspaceDenied): find(content=fs.ContentFilter(query='SECRET'),on_error='skip')
    event=json.loads((tmp_path/'incidents.jsonl').read_text())
    assert event['code']=='symlink_forbidden' and 'SECRET' not in json.dumps(event)

@pytest.mark.parametrize('extra', [{'content':{'query':''}},{'content':{'query':'x','extra':1}},{'content':{'query':'x','max_bytes':0}},{'content':{'query':'x'},'type':'directory'}])
def test_strict_input(root,extra):
    with pytest.raises(ValueError): fs.FindInput(path='/',**extra)

def test_only_find_and_standalone_cli(root,tmp_path):
    (root/'hello.py').write_text('TODO example')
    script=BASE/'tools/fs_find/tool.py'
    p=subprocess.run([sys.executable,str(script),json.dumps({'path':'/','content':{'query':'TODO'}})],cwd=tmp_path,capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    r=json.loads(p.stdout);assert r['total']==1 and r['entries'][0]['path']=='/hello.py'
    for tool in ['fs_find','fs_glob','fs_list']:
        p=subprocess.run([sys.executable,str(BASE/'tools'/tool/'run.py'),'{"describe":"json_spec"}'],capture_output=True,text=True)
        schema=json.loads(p.stdout)['inputSchema']
        assert ('content' in schema['properties'])==(tool=='fs_find')
        assert schema['x-schema-version']==('2.2.0' if tool=='fs_find' else '2.1.0')
