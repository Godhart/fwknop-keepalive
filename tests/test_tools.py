import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from spa_config import validate, generate, script, load

@pytest.fixture
def profile():
    return dict(version=1,name='Test',server='127.0.0.1',spa_port=62201,access='tcp/22,tcp/443',allow_ip='source',username='mobile',interval_seconds=60,access_timeout_seconds=300,key_base64=base64.b64encode(bytes(range(32))).decode(),hmac_key_base64=base64.b64encode(bytes(range(32,64))).decode())

@pytest.mark.parametrize('field,value',[
    ('server','example.org\nKEY bad'),('server','example.org\n'),('server','$(touch /tmp/unsafe)'),
    ('spa_port',True),('spa_port',0),('access','tcp/65536'),('access','tcp/0'),
    ('allow_ip','1.2.3.999'),('allow_ip','0.0.0.0'),('allow_ip','01.2.3.4'),
    ('interval_seconds',300),('username','hi\nthere'),('version',2),
    ('key_base64','aaaa'),('hmac_key_base64','x'*43+'!')])
def test_invalid(profile,field,value):
    profile[field]=value
    with pytest.raises(ValueError): validate(profile)

def test_unknown(profile):
    profile['extra']=1
    with pytest.raises(ValueError): validate(profile)

def test_duplicate(tmp_path):
    p=tmp_path/'p.yaml';p.write_text('version: 1\nversion: 1\n')
    with pytest.raises(ValueError):load(p)

def test_generate(profile,tmp_path):
    out=generate(profile,tmp_path/'output')
    assert json.loads((out/'profile.json').read_text())==profile
    assert (out/'profile-qr.png').read_bytes().startswith(b'\x89PNG')
    assert (out/'profile.json').stat().st_mode & 0o777==0o600
    assert (out/'keepalive.sh').stat().st_mode & 0o777==0o700
    subprocess.run(['bash','-n',str(out/'keepalive.sh')],check=True)
    with pytest.raises(FileExistsError):generate(profile,out)

def test_script_execution(profile,tmp_path):
    # Execute the actual script with a CLI substitute, observe its private rc
    # without printing keys and ensure the temporary file disappears.
    stub=tmp_path/'fwknop'
    stub.write_text('#!/bin/bash\n[[ "$1" == --rc-file ]] || exit 9\nprintf "%s" "$2" > "$CAPTURE_PATH"\ncp "$2" "$CAPTURE_CONFIG"\n')
    stub.chmod(0o700)
    out=generate(profile,tmp_path/'out')
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],CAPTURE_PATH=str(tmp_path/'path'),CAPTURE_CONFIG=str(tmp_path/'config'))
    result=subprocess.run([str(out/'keepalive.sh'),'--once'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode==0,result.stderr
    assert not Path((tmp_path/'path').read_text()).exists()
    rc=(tmp_path/'config').read_text()
    assert 'ALLOW_IP 0.0.0.0' in rc
    assert 'FW_TIMEOUT 300' in rc
    assert profile['key_base64'] not in result.stdout+result.stderr

def test_schema_asset():
    assert json.loads((ROOT/'profile.schema.json').read_text())==json.loads((ROOT/'android/app/src/main/assets/profile.schema.json').read_text())

def test_once_returns_cli_failure(profile,tmp_path):
    stub=tmp_path/'fwknop'
    stub.write_text('#!/bin/bash\nexit 7\n');stub.chmod(0o700)
    out=generate(profile,tmp_path/'out')
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'])
    result=subprocess.run([str(out/'keepalive.sh'),'--once'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode==7
    assert 'failed' in result.stderr
