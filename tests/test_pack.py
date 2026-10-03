import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE/'src'))
import common as fs

@pytest.fixture(autouse=True)
def configured_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv('TWYLT_WORKSPACE_ROOT', str(tmp_path))
    monkeypatch.delenv('TWYLT_INCIDENT_LOG', raising=False)

def vp(path):
    return '/' + Path(path).relative_to(Path(os.environ['TWYLT_WORKSPACE_ROOT'])).as_posix()

@pytest.fixture
def tree(tmp_path):
    (tmp_path/'a.txt').write_text('one\r\ntwo\nthree', newline='')
    (tmp_path/'b.py').write_text('print(1)')
    (tmp_path/'.hidden').write_text('hidden')
    (tmp_path/'sub').mkdir()
    (tmp_path/'sub'/'c.py').write_text('pass')
    (tmp_path/'sub'/'deep').mkdir()
    (tmp_path/'sub'/'deep'/'d.txt').write_text('deep')
    return tmp_path

def scan(path, cls=fs.SearchInput, **kw):
    return fs.search(cls(path=vp(path), **kw))

@pytest.mark.parametrize('depth,total', [(0,0),(1,4),(2,6),(3,7),(None,7)])
def test_depth(tree, depth, total):
    assert scan(tree, max_depth=depth).total == total


def test_pagination(tree):
    all_entries = scan(tree, max_depth=None).entries
    result=[]; offset=0
    while True:
        page=scan(tree,max_depth=None, offset=offset,limit=2)
        assert page.total == 7
        result.extend(page.entries)
        if page.next_offset is None: break
        offset=page.next_offset
    assert result == all_entries
    assert scan(tree,offset=100).entries == []


def test_filters_do_not_prune(tree):
    r=scan(tree,fs.FindInput,type='file',name_regex=r'\.py$')
    assert {e.relative_path for e in r.entries} == {'b.py','sub/c.py'}
    assert scan(tree,fs.FindInput,path_regex='deep/',type='file').total == 1
    assert scan(tree,fs.FindInput,include_hidden=False).total == 6

@pytest.mark.parametrize('pattern,expected', [
    ('*.py',{'b.py'}), ('**/*.py',{'b.py','sub/c.py'}),
    ('sub/*',{'sub/c.py','sub/deep'}), ('sub/**/*.txt',{'sub/deep/d.txt'}),
    ('**/c.?y',{'sub/c.py'}), ('[ab].*',{'a.txt','b.py'}), ('**', {'.hidden','a.txt','b.py','sub','sub/c.py','sub/deep','sub/deep/d.txt'}),
])
def test_glob(tree,pattern,expected):
    assert {e.relative_path for e in scan(tree,fs.GlobInput,pattern=pattern).entries} == expected

@pytest.mark.parametrize('pattern', ['/tmp/*','../*','a/**x','a//b'])
def test_glob_invalid(tree,pattern):
    with pytest.raises(ValueError): scan(tree,fs.GlobInput,pattern=pattern)

@pytest.mark.skipif(os.name!='posix',reason='POSIX metadata')
def test_permissions_owner(tree):
    import pwd
    (tree/'a.txt').chmod(0o640)
    assert scan(tree,name_regex='a.txt',permissions='640').total == 1
    assert scan(tree,name_regex='a.txt',permissions='600',permission_match='all').total == 1
    assert scan(tree,name_regex='a.txt',permissions='111',permission_match='any').total == 0
    assert scan(tree,owner=os.getuid()).total == 4
    assert scan(tree,owner=pwd.getpwuid(os.getuid()).pw_name,access='r').total == 4


def test_invalid_search(tree):
    with pytest.raises(fs.re.error): scan(tree,name_regex='[')
    with pytest.raises(ValueError,match='max_entries'): scan(tree,max_entries=1)
    with pytest.raises(ValueError): scan(tree/'a.txt')


def symlink_or_skip(link,target,is_dir=False):
    try: link.symlink_to(target,target_is_directory=is_dir)
    except OSError: pytest.skip('Symlinks unavailable')


def test_links(tree):
    symlink_or_skip(tree/'loop',tree,True)
    symlink_or_skip(tree/'broken',tree/'absent')
    result=scan(tree,fs.FindInput)
    assert result.total == 9
    assert scan(tree,fs.FindInput,type='symlink').total == 2
    with pytest.raises(ValueError): scan(tree/'loop')
    with pytest.raises(fs.WorkspaceDenied): fs.delete(fs.DeleteInput(path=vp(tree/'loop'),recursive=True))
    assert (tree/'a.txt').exists()


def test_skipped_errors(tree,monkeypatch):
    original=os.scandir
    def fail(path):
        if Path(path).name=='sub': raise PermissionError('denied')
        return original(path)
    monkeypatch.setattr(os,'scandir',fail)
    with pytest.raises(PermissionError): scan(tree,fs.FindInput)
    r=scan(tree,fs.FindInput,on_error='skip')
    assert not r.complete and r.error_count == 1 and len(r.errors) == 1


def test_read_lines(tree):
    r=fs.read_text(fs.ReadInput(path=vp(tree/'a.txt'),offset=1,count=1))
    assert r.text=='two\n' and r.total_lines==3 and r.next_offset==2
    assert fs.read_text(fs.ReadInput(path=vp(tree/'a.txt'),offset=20)).text==''
    assert fs.read_text(fs.ReadInput(path=vp(tree/'a.txt'),count=0)).lines_returned==0
    assert fs.read_text(fs.ReadInput(path=vp(tree/'a.txt'),count=None)).text=='one\r\ntwo\nthree'

@pytest.mark.parametrize('encoding', ['utf-8','utf-8-sig','utf-16','utf-32','cp1251'])
def test_encodings(tmp_path,encoding):
    p=tmp_path/'text'; p.write_bytes('Привет мир\n'.encode(encoding))
    assert fs.read_text(fs.ReadInput(path=vp(p),encoding=encoding)).text=='Привет мир\n'
    if encoding!='cp1251': assert fs.read_text(fs.ReadInput(path=vp(p))).text=='Привет мир\n'


def test_auto_legacy(tmp_path):
    p=tmp_path/'text'; p.write_bytes(('Это длинный русский текст для проверки кодировки. '*30).encode('cp1251'))
    r=fs.read_text(fs.ReadInput(path=vp(p)))
    assert r.detected and r.encoding and r.text


def test_read_edges(tmp_path):
    p=tmp_path/'text'; p.write_bytes(b'')
    assert fs.read_text(fs.ReadInput(path=vp(p))).total_lines==0
    p.write_bytes(b'a\rb\r')
    assert fs.read_text(fs.ReadInput(path=vp(p))).total_lines==2
    with pytest.raises(ValueError,match='max_bytes'): fs.read_text(fs.ReadInput(path=vp(p),max_bytes=1))
    p.write_bytes(b'\x00binary')
    with pytest.raises(ValueError): fs.read_text(fs.ReadInput(path=vp(p)))

@pytest.mark.parametrize('fmt', ['json','yaml','toml'])
def test_structured_roundtrip(tmp_path,fmt):
    p=tmp_path/('settings.'+fmt); data={'name':'Привет','enabled':True,'list':[1,2], 'nested':{'x':'y'}}
    fs.write_jyt(fs.WriteJytInput(path=vp(p),data=data))
    assert fs.read_jyt(fs.JytInput(path=vp(p))).data==data

@pytest.mark.parametrize('suffix,text', [('json','{"x":1,"x":2}'),('yaml','x: 1\nx: 2'),('yaml','1: value'),('yaml','x: !!python/object:object {}'),('json','{"x":NaN}'),('yaml','x: &x [*x]')])
def test_bad_structured(tmp_path,suffix,text):
    p=tmp_path/('bad.'+suffix); p.write_text(text)
    with pytest.raises((ValueError,fs.yaml.YAMLError)): fs.read_jyt(fs.JytInput(path=vp(p)))


def test_dates_and_null(tmp_path):
    p=tmp_path/'x.toml'; p.write_text('date = 2026-10-01\n')
    assert fs.read_jyt(fs.JytInput(path=vp(p))).data['date']=='2026-10-01'
    with pytest.raises((ValueError,TypeError)): fs.write_jyt(fs.WriteJytInput(path=vp(tmp_path/'null.toml'),data={'x':None}))
    assert not (tmp_path/'null.toml').exists()
    with pytest.raises(ValueError): fs.write_jyt(fs.WriteJytInput(path=vp(tmp_path/'list.toml'),data=[]))


def test_markdown(tmp_path):
    p=tmp_path/'x.md'; p.write_text('# Heading\n\nHello **world** [link](https://example.com).\n\n- one\n- two\n\n```py\nx = 1\n```\n\n| A | B |\n|---|---|\n| 1 | 2 |\n')
    r=fs.read_markdown(fs.MarkdownInput(path=vp(p)))
    types=[n['type'] for n in r.nodes]
    assert types==['heading','paragraph','bullet_list','fence','table']
    assert r.nodes[0]['lines']==[0,1]
    assert r.nodes[0]['children'][0]['children'][0]['content']=='Heading'
    assert 'strong' in json.dumps(r.nodes)


def test_write(tmp_path):
    p=tmp_path/'dir'/'x.txt'
    with pytest.raises(FileNotFoundError): fs.write_text(fs.WriteInput(path=vp(p),content='one'))
    fs.write_text(fs.WriteInput(path=vp(p),content='one',create_parents=True))
    with pytest.raises(FileExistsError): fs.write_text(fs.WriteInput(path=vp(p),content='two'))
    assert p.read_text()=='one'
    p.chmod(0o640)
    fs.write_text(fs.WriteInput(path=vp(p),content='two',overwrite=True))
    assert p.read_text()=='two'
    if os.name=='posix': assert p.stat().st_mode & 0o777 == 0o640
    with pytest.raises(UnicodeEncodeError): fs.write_text(fs.WriteInput(path=vp(p),content='Привет',encoding='ascii',overwrite=True))
    assert p.read_text()=='two'
    assert not list(p.parent.glob('.fs-twylt-*'))


def test_write_symlink(tmp_path):
    p=tmp_path/'original'; p.write_text('original')
    symlink_or_skip(tmp_path/'link',p)
    with pytest.raises(ValueError): fs.write_text(fs.WriteInput(path=vp(tmp_path/'link'),content='bad',overwrite=True))
    assert p.read_text()=='original'

@pytest.mark.parametrize('operation', ['copy','move'])
def test_transfers(tmp_path,operation):
    a=tmp_path/'a'; b=tmp_path/'nested'/'b'; a.write_text('hello')
    fs.transfer(fs.TransferInput(source=vp(a),destination=vp(b),create_parents=True),operation)
    assert b.read_text()=='hello'
    assert a.exists() == (operation=='copy')
    a.write_text('replacement')
    with pytest.raises(FileExistsError): fs.transfer(fs.TransferInput(source=vp(a),destination=vp(b)),operation)
    fs.transfer(fs.TransferInput(source=vp(a),destination=vp(b),overwrite=True),operation)
    assert b.read_text()=='replacement'

@pytest.mark.parametrize('operation', ['copy','move'])
def test_directory_transfer(tmp_path,operation):
    a=tmp_path/'a'; a.mkdir(); (a/'file').write_text('hello')
    b=tmp_path/'b'
    with pytest.raises(ValueError): fs.transfer(fs.TransferInput(source=vp(a),destination=vp(a/'inside')),operation)
    fs.transfer(fs.TransferInput(source=vp(a),destination=vp(b)),operation)
    assert (b/'file').read_text()=='hello'
    a.mkdir(exist_ok=True)
    with pytest.raises(ValueError): fs.transfer(fs.TransferInput(source=vp(a),destination=vp(b),overwrite=True),operation)


def test_copy_links(tmp_path):
    target=tmp_path/'target'; target.write_text('hello')
    link=tmp_path/'link'; symlink_or_skip(link,target)
    copy=tmp_path/'copy'
    with pytest.raises(fs.WorkspaceDenied):
        fs.transfer(fs.TransferInput(source=vp(link),destination=vp(copy)),'copy')
    assert not copy.exists() and link.is_symlink()


def test_delete(tmp_path):
    p=tmp_path/'dir'; p.mkdir(); (p/'x').write_text('keep')
    with pytest.raises(ValueError): fs.delete(fs.DeleteInput(path=vp(p)))
    assert not fs.delete(fs.DeleteInput(path=vp(p),recursive=True,dry_run=True)).changed
    assert (p/'x').exists()
    assert fs.delete(fs.DeleteInput(path=vp(p),recursive=True)).changed
    assert not p.exists()
    assert not fs.delete(fs.DeleteInput(path=vp(p),missing_ok=True)).changed
    with pytest.raises(FileNotFoundError): fs.delete(fs.DeleteInput(path=vp(p)))
    with pytest.raises(ValueError): fs.delete(fs.DeleteInput(path='/',recursive=True))

TOOLS=sorted((BASE/'tools').iterdir())

@pytest.mark.parametrize('folder',TOOLS,ids=lambda p:p.name)
def test_describe_and_schemas(folder,tmp_path):
    p=subprocess.run([sys.executable,str(folder/'run.py'),'{"describe":"json_spec"}'],cwd=tmp_path,capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    spec=json.loads(p.stdout)
    assert spec['name']==folder.name and spec['version']=='0.5.0'
    assert spec['inputSchema']['additionalProperties'] is False
    assert spec['outputSchema']['properties']
    assert spec['requirements']['content'].startswith('twylt==1.0.0')
    assert spec['few_shots']
    p=subprocess.run([sys.executable,str(folder/'run.py'),'{"unexpected":1}'],cwd=tmp_path,capture_output=True,text=True)
    assert p.returncode!=0
    assert json.loads(p.stdout or p.stderr)


def test_cli_io(tmp_path):
    p=tmp_path/'text.txt'
    args={'path':vp(p),'content':'hello\n'}
    script=str(BASE/'tools/fs_write/run.py')
    process=subprocess.run([sys.executable,script,json.dumps(args)],cwd=tmp_path,capture_output=True,text=True)
    assert process.returncode==0,process.stderr+process.stdout
    assert json.loads(process.stdout)['changed']
    process=subprocess.run([sys.executable,str(BASE/'tools/fs_read/run.py')],input=json.dumps({'path':vp(p)}),cwd=tmp_path,capture_output=True,text=True)
    assert process.returncode==0,process.stderr+process.stdout
    assert json.loads(process.stdout)['text']=='hello\n'


def test_bootstrap_without_business_dependencies(tmp_path):
    # TWYLT and its own dependencies are installed; emulate absent business dependency.
    code = """import sys
import importlib.abc
class BlockYaml(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'yaml': raise ModuleNotFoundError('yaml intentionally blocked')
sys.meta_path.insert(0, BlockYaml())
from twylt.bootstrap import run_tool_file
run_tool_file(sys.argv[1])
"""
    process=subprocess.run([sys.executable,'-c',code,str(BASE/'tools/fs_read/tool.py')],env={**os.environ,'INPUT_DESCRIBE':'requirements'},capture_output=True,text=True,cwd=tmp_path)
    assert process.returncode==0,process.stderr+process.stdout
    assert 'twylt==1.0.0' in process.stdout


def test_file_io_and_standalone(tmp_path):
    import shutil
    standalone=tmp_path/'tool.py'
    shutil.copy2(BASE/'tools/fs_write/tool.py',standalone)
    (tmp_path/'input.json').write_text(json.dumps({'path':'out.txt','content':'standalone'}))
    process=subprocess.run([sys.executable,str(standalone)],stdin=subprocess.DEVNULL,capture_output=True,text=True,cwd=tmp_path)
    assert process.returncode==0,process.stderr+process.stdout
    assert (tmp_path/'out.txt').read_text()=='standalone'
    assert json.loads((tmp_path/'output.json').read_text())['changed']


@pytest.mark.parametrize('op', ['list','find','glob'])
def test_generated_search(op,tree):
    args={'path':vp(tree),'type':'file','max_depth':None}
    if op=='glob': args['pattern']='**/*.py'
    else: args['name_regex']=r'\.py$'
    p=subprocess.run([sys.executable,str(BASE/'tools'/('fs_'+op)/'run.py'),json.dumps(args)],capture_output=True,text=True)
    assert p.returncode==0,p.stderr+p.stdout
    assert json.loads(p.stdout)['total']==2


def test_move_broken_link_over_file(tmp_path):
    link=tmp_path/'link'; symlink_or_skip(link,tmp_path/'absent')
    destination=tmp_path/'dest'; destination.write_text('replace')
    with pytest.raises(fs.WorkspaceDenied):
        fs.transfer(fs.TransferInput(source=vp(link),destination=vp(destination),overwrite=True),'move')
    assert destination.read_text() == 'replace' and link.is_symlink()
