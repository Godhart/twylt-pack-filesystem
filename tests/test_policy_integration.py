import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
BASE=Path(__file__).resolve().parents[1]
TOOLS=sorted(p for p in (BASE/'tools').iterdir() if p.is_dir())

def call(op,data,env):
    return subprocess.run([sys.executable,str(BASE/'tools'/op/'run.py'),json.dumps(data)],env=env,text=True,capture_output=True,timeout=20)

def setup_env(tmp_path):
    root=tmp_path/'ws';root.mkdir()
    log=tmp_path/'audit.jsonl'
    env={**os.environ,'TWYLT_WORKSPACE_ROOT':str(root),'TWYLT_INCIDENT_LOG':str(log)}
    env.pop('INPUT_DESCRIBE',None)
    return root,log,env

@pytest.mark.parametrize('tool',TOOLS,ids=lambda p:p.name)
def test_every_tool_requires_root(tool,tmp_path):
    env={**os.environ};env.pop('TWYLT_WORKSPACE_ROOT',None);env.pop('TWYLT_INCIDENT_LOG',None);env.pop('INPUT_DESCRIBE',None)
    result=call(tool.name,json.loads((tool/'example.json').read_text()),env)
    assert result.returncode==5 and not result.stdout
    event=json.loads(result.stderr.splitlines()[0])
    assert event['code']=='workspace_not_configured' and event['tool']==tool.name
    described=call(tool.name,{'describe':'json_spec'},env)
    assert described.returncode==0 and json.loads(described.stdout)['name']==tool.name

@pytest.mark.parametrize('tool',TOOLS,ids=lambda p:p.name)
def test_every_tool_checks_log_before_business(tool,tmp_path):
    root,log,env=setup_env(tmp_path)
    env['TWYLT_INCIDENT_LOG']=str(tmp_path/'absent'/'audit.jsonl')
    result=call(tool.name,json.loads((tool/'example.json').read_text()),env)
    assert result.returncode==5
    assert json.loads(result.stderr.splitlines()[0])['code']=='incident_log_unavailable'
    assert list(root.iterdir())==[]

def test_virtual_operations_and_incidents(tmp_path):
    root,log,env=setup_env(tmp_path)
    p=call('fs_write',{'path':'/sub/a.txt','content':'secret payload','create_parents':True},env)
    assert p.returncode==0 and json.loads(p.stdout)['path']=='/sub/a.txt'
    assert (root/'sub/a.txt').read_text()=='secret payload'
    p=call('fs_read',{'path':'sub/a.txt'},env)
    assert p.returncode==0 and json.loads(p.stdout)['path']=='/sub/a.txt'
    p=call('fs_list',{'path':'/','max_depth':2},env)
    assert {e['path'] for e in json.loads(p.stdout)['entries']}=={'/sub','/sub/a.txt'}
    (root/'link').symlink_to(tmp_path)
    cases=[('fs_read',{'path':'/link/outside'}),
           ('fs_write',{'path':'../outside','content':'secret payload'}),
           ('fs_copy',{'source':'/sub/a.txt','destination':'../outside'}),
           ('fs_move',{'source':'/sub/a.txt','destination':'/link/dest'}),
           ('fs_delete',{'path':'/','recursive':True}),
           ('fs_write_jyt',{'path':'/link/a.json','data':{'secret':'payload'}})]
    for op,data in cases:
        result=call(op,data,env)
        assert result.returncode==5 and not result.stdout
    records=[json.loads(s) for s in log.read_text().splitlines()]
    assert len(records)==len(cases) and 'secret payload' not in log.read_text()
    assert all(record['incident_id'] for record in records)
    assert (root/'sub/a.txt').read_text()=='secret payload'
    assert not (tmp_path/'outside').exists()

@pytest.mark.parametrize('op', ['fs_copy','fs_move','fs_delete'])
def test_recursive_symlink_rejected_before_mutation(tmp_path,op):
    root,log,env=setup_env(tmp_path)
    source=root/'source';source.mkdir();(source/'file').write_text('keep')
    (source/'nested').mkdir();(source/'nested/link').symlink_to(tmp_path)
    data={'path':'/source','recursive':True} if op=='fs_delete' else {'source':'/source','destination':'/dest'}
    result=call(op,data,env)
    assert result.returncode==5 and (source/'file').read_text()=='keep' and not (root/'dest').exists()
    assert json.loads(log.read_text())['code']=='symlink_forbidden'


def test_file_transport_cannot_escape(tmp_path):
    root,log,env=setup_env(tmp_path)
    tool=TOOLS[0]
    (tmp_path/'output.json').write_text('keep outside')
    p=subprocess.run([sys.executable,str(tool/'run.py')],cwd=tmp_path,stdin=subprocess.DEVNULL,env=env,text=True,capture_output=True)
    assert p.returncode==4 and (tmp_path/'output.json').read_text()=='keep outside'
    assert json.loads(log.read_text())['code']=='transport_cwd_outside_workspace'
    log.write_text('')
    target=tmp_path/'outside';target.write_text('keep target')
    (root/'output.json').symlink_to(target)
    p=subprocess.run([sys.executable,str(tool/'run.py')],cwd=root,stdin=subprocess.DEVNULL,env=env,text=True,capture_output=True)
    assert p.returncode==4 and target.read_text()=='keep target' and (root/'output.json').is_symlink()
    assert json.loads(log.read_text())['code']=='symlink_forbidden'
