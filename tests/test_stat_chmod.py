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
    monkeypatch.setenv('TWYLT_INCIDENT_LOG',str(tmp_path/'audit.jsonl'))
    return root

@pytest.mark.parametrize('text,lines', [('',0),('x',1),('x\n',1),('\n',1),('x\n\n',2),('x\r\ny\rz\nlast',4),('a\u2028b',1)])
def test_stat_lines(root,text,lines):
    p=root/'text';p.write_bytes(text.encode('utf-8'))
    r=fs.file_stat(fs.StatInput(path='/text'))
    assert r.path=='/text' and r.size_bytes==len(p.read_bytes())
    assert r.content_type=='text' and r.line_count==lines and r.encoding=='utf-8'
    assert r.reason=='decoded_text'

@pytest.mark.parametrize('encoding', ['utf-8-sig','utf-16','utf-32','cp1251'])
def test_stats_encoding(root,encoding):
    payload='Привет\nмир'.encode(encoding);(root/'text').write_bytes(payload)
    r=fs.file_stat(fs.StatInput(path='text',encoding=encoding))
    assert r.content_type=='text' and r.line_count==2 and r.size_bytes==len(payload)
    if encoding!='cp1251': assert fs.file_stat(fs.StatInput(path='text')).line_count==2
    else: assert fs.file_stat(fs.StatInput(path='text')).content_type=='unknown'

@pytest.mark.parametrize('raw', [b'\0hello',b'\x01abc',b'\x89PNG\r\n\x1a\nrest',b'PK\x03\x04data',b'%PDF-1.7\ntext',b'\x7fELFdata'])
def test_binary(root,raw):
    (root/'data').write_bytes(raw)
    r=fs.file_stat(fs.StatInput(path='data'))
    assert r.content_type=='binary' and r.line_count is None and r.encoding is None
    assert r.size_bytes==len(raw)

def test_unknown_limits_and_errors(root):
    (root/'text').write_bytes(b'abcdef\n')
    r=fs.file_stat(fs.StatInput(path='text',max_bytes=3))
    assert r.content_type=='unknown' and r.reason=='size_limit' and r.line_count is None and r.size_bytes==7
    (root/'text').write_bytes(b'\xff\xfe\x61')
    r=fs.file_stat(fs.StatInput(path='text'))
    assert r.content_type=='unknown' and r.reason=='undecodable'
    with pytest.raises(LookupError): fs.file_stat(fs.StatInput(path='text',encoding='madeup'))
    with pytest.raises(ValueError): fs.file_stat(fs.StatInput(path='/'))
    with pytest.raises(FileNotFoundError): fs.file_stat(fs.StatInput(path='absent'))

@pytest.mark.parametrize('cls,extra', [(fs.SearchInput,{}),(fs.FindInput,{}),(fs.GlobInput,{'pattern':'**/*'})])
def test_search_stats_only_page(root,monkeypatch,cls,extra):
    (root/'a.txt').write_text('a\n');(root/'b.txt').write_text('b\nc');(root/'dir').mkdir()
    original=fs.inspect_file;seen=[]
    def spy(data): seen.append(data.path);return original(data)
    monkeypatch.setattr(fs,'inspect_file',spy)
    no_stats=fs.search(cls(path='/',**extra))
    assert not seen and all(e.stats is None for e in no_stats.entries)
    page=fs.search(cls(path='/',include_stats=True,offset=1,limit=1,**extra))
    assert seen==['/b.txt'] and page.total==3 and page.entries[0].stats.line_count==2
    result=fs.search(cls(path='/',include_stats=True,**extra))
    assert result.entries[2].stats is None

def test_search_stats_options_content_and_skip(root,monkeypatch):
    (root/'a').write_bytes('Привет\n'.encode('cp1251'))
    r=fs.search(fs.FindInput(path='/',content=fs.ContentFilter(query='Привет',encoding='cp1251'),include_stats=True,stats_encoding='cp1251'))
    assert r.total==1 and r.entries[0].stats.line_count==1
    r=fs.search(fs.SearchInput(path='/',include_stats=True,stats_max_bytes=1))
    assert r.entries[0].stats.content_type=='unknown' and r.complete
    def fail(data): raise PermissionError('Cannot read stats')
    monkeypatch.setattr(fs,'inspect_file',fail)
    with pytest.raises(PermissionError): fs.search(fs.SearchInput(path='/',include_stats=True))
    r=fs.search(fs.SearchInput(path='/',include_stats=True,on_error='skip'))
    assert r.total==1 and len(r.entries)==1 and r.entries[0].stats is None
    assert not r.complete and r.error_count==1 and r.errors[0].path=='/a'

@pytest.mark.skipif(os.name!='posix',reason='POSIX chmod')
def test_chmod_regular_directory_and_dry_run(root):
    p=root/'text';p.write_text('keep');p.chmod(0o600)
    r=fs.chmod(fs.ChmodInput(path='text',mode='0640'))
    assert r.previous_mode=='0600' and r.mode=='0640' and r.changed
    assert p.stat().st_mode & 0o7777==0o640 and p.read_text()=='keep'
    assert not fs.chmod(fs.ChmodInput(path='text',mode='640')).changed
    r=fs.chmod(fs.ChmodInput(path='text',mode='000',dry_run=True))
    assert not r.changed and r.mode=='0640' and r.requested_mode=='0000'
    d=root/'dir';d.mkdir();(d/'child').write_text('x');(d/'child').chmod(0o600)
    assert fs.chmod(fs.ChmodInput(path='dir',mode='0750')).mode=='0750'
    assert (d/'child').stat().st_mode & 0o777==0o600
    with pytest.raises(fs.WorkspaceDenied): fs.chmod(fs.ChmodInput(path='/',mode='700'))

@pytest.mark.parametrize('mode', ['rwx','u+x','888',644,'77','10000','-1'])
def test_chmod_mode_validation(mode):
    with pytest.raises(ValueError): fs.ChmodInput(path='text',mode=mode)

def test_new_operations_policy(root,tmp_path):
    outside=tmp_path/'outside';outside.write_text('keep');outside.chmod(0o600)
    (root/'link').symlink_to(outside)
    for op,data in [('stat',{'path':'/link'}),('chmod',{'path':'/link','mode':'777'}),('chmod',{'path':'../outside','mode':'777'})]:
        p=subprocess.run([sys.executable,str(BASE/'tools'/('fs_'+op)/'run.py'),json.dumps(data)],capture_output=True,text=True)
        assert p.returncode==6,p.stderr
    assert outside.read_text()=='keep' and outside.stat().st_mode & 0o777==0o600
    events=[json.loads(s) for s in (tmp_path/'audit.jsonl').read_text().splitlines()]
    assert len(events)==3 and {e['tool'] for e in events}=={'fs_stat','fs_chmod'}

def test_cli_and_schemas(root):
    (root/'text').write_text('hello\n')
    for op,data in [('stat',{'path':'text'}),('chmod',{'path':'text','mode':'0644','dry_run':True})]:
        p=subprocess.run([sys.executable,str(BASE/'tools'/('fs_'+op)/'run.py'),json.dumps(data)],capture_output=True,text=True)
        assert p.returncode==0,p.stderr
        assert json.loads(p.stdout)['path']=='/text'
        p=subprocess.run([sys.executable,str(BASE/'tools'/('fs_'+op)/'run.py'),'{"describe":"json_spec"}'],capture_output=True,text=True)
        spec=json.loads(p.stdout)
        assert spec['inputSchema']['x-schema-version']=='1.0.0'
        assert spec['outputSchema']['x-schema-version']==('1.1.0' if op=='stat' else '1.0.0')

@pytest.mark.parametrize('text,ending,indent', [
    ('','none','none'), ('hello','none','none'),
    ('a\nb\n','lf','none'), ('a\r\nb\r\n','crlf','none'), ('a\rb\r','cr','none'),
    ('a\r\nb\nc\r','mixed','none'), ('  x\n    y\n','lf','space'),
    ('\tx\n\t\ty','lf','tab'), ('  x\n\ty','lf','mixed'),
    (' \tx','none','mixed'), ('\t \n   \nplain','lf','none'),
    ('x\ty\n  a b','lf','space'),
])
def test_text_layout(root,text,ending,indent):
    (root/'text').write_bytes(text.encode())
    r=fs.file_stat(fs.StatInput(path='text'))
    assert r.line_ending==ending and r.indentation==indent and r.encoding_source=='utf8'

@pytest.mark.parametrize('codec', ['utf-8-sig','utf-16','utf-32'])
def test_bom_layout(root,codec):
    (root/'text').write_bytes('  Привет\r\n\tмир'.encode(codec))
    r=fs.file_stat(fs.StatInput(path='text'))
    assert r.encoding_source=='bom' and r.line_ending=='crlf' and r.indentation=='mixed'
    assert r.line_count==2

def test_explicit_and_nontext_layout(root):
    (root/'text').write_bytes('  Привет\n'.encode('cp1251'))
    r=fs.file_stat(fs.StatInput(path='text',encoding='cp1251'))
    assert r.encoding=='cp1251' and r.encoding_source=='explicit' and r.indentation=='space'
    for raw in [b'\0binary', b'\xff']:
        (root/'text').write_bytes(raw)
        r=fs.file_stat(fs.StatInput(path='text'))
        assert r.encoding_source is None and r.line_ending is None and r.indentation is None

@pytest.mark.parametrize('cls,extra', [(fs.SearchInput,{}),(fs.FindInput,{}),(fs.GlobInput,{'pattern':'**/*'})])
def test_layout_in_search(root,cls,extra):
    (root/'text').write_bytes(b'\tx\r\n')
    r=fs.search(cls(path='/',include_stats=True,**extra))
    stats=r.entries[0].stats
    assert stats.line_ending=='crlf' and stats.indentation=='tab' and stats.encoding_source=='utf8'
