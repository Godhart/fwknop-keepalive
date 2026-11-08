import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from profile_crypto import protect, unlock
from spa_config import generate, load
from test_tools import profile

PASSWORD='пароль 🔑 Test 123'

def test_roundtrip(profile):
    a=protect(profile,PASSWORD);b=protect(profile,PASSWORD)
    assert a!=b and unlock(a,PASSWORD)==profile
    text=json.dumps(a)
    assert profile['key_base64'] not in text and profile['hmac_key_base64'] not in text
    assert profile['server'] not in text
    with pytest.raises(ValueError):unlock(a,'incorrect')
    for field in ['salt','nonce','ciphertext']:
        bad=copy.deepcopy(a);raw=bytearray(base64.b64decode(bad[field]));raw[0]^=1
        bad[field]=base64.b64encode(raw).decode()
        with pytest.raises(ValueError):unlock(bad,PASSWORD)
    for field,value in [('iterations',1),('iterations',600000.0),('version',3),('kdf','other'),('extra','bad')]:
        bad=dict(a);bad[field]=value
        with pytest.raises(ValueError):unlock(bad,PASSWORD)

def test_export(profile,tmp_path):
    out=generate(profile,tmp_path/'protected',password=PASSWORD)
    payload=json.loads((out/'profile.json').read_text())
    assert load(out/'profile.json',PASSWORD)==profile
    assert unlock(payload,PASSWORD)==profile
    script=(out/'keepalive.sh').read_text()
    assert PASSWORD not in script and profile['key_base64'] not in script
    subprocess.run(['bash','-n',str(out/'keepalive.sh')],check=True)
    with pytest.raises(ValueError):load(out/'profile.json','wrong')

@pytest.mark.skipif(not shutil.which('java'),reason='Java 17 required')
def test_java_decryption(profile,tmp_path):
    root=Path(__file__).resolve().parents[1]
    source=root/'android/app/src/main/java/org/example/spakeepalive/ProfileCrypto.java'
    probe=tmp_path/'Probe.java'
    probe.write_text('''package org.example.spakeepalive;
import java.nio.file.*; import java.util.*;
public class Probe {public static void main(String[] args)throws Exception {
List<String> lines=Files.readAllLines(Path.of(args[0]));
byte[] result=ProfileCrypto.decrypt(lines.get(0).toCharArray(),ProfileCrypto.base64(lines.get(1)),ProfileCrypto.base64(lines.get(2)),ProfileCrypto.base64(lines.get(3)),600000);
System.out.write(result);
}}''')
    subprocess.run(['java','--module','jdk.compiler/com.sun.tools.javac.Main','-d',str(tmp_path),str(source),str(probe)],check=True,capture_output=True)
    env=protect(profile,PASSWORD)
    data=tmp_path/'input';data.write_text('\n'.join([PASSWORD,env['salt'],env['nonce'],env['ciphertext']]))
    cmd=['java','-cp',str(tmp_path),'org.example.spakeepalive.Probe',str(data)]
    result=subprocess.run(cmd,check=True,capture_output=True)
    assert json.loads(result.stdout)==profile
    data.write_text('\n'.join(['wrong',env['salt'],env['nonce'],env['ciphertext']]))
    assert subprocess.run(cmd,capture_output=True).returncode!=0

@pytest.mark.parametrize('loop',[False,True])
def test_script_password_and_loop(profile,tmp_path,loop):
    import pexpect
    stub=tmp_path/'fwknop'
    stub.write_text('#!/bin/bash\nprintf "sent\\n" >> "$COUNT_FILE"\ncp "$2" "$RC_FILE"\nprintf "%s" "$2" > "$PATH_FILE"\n')
    stub.chmod(0o700)
    if loop:
        sleeper=tmp_path/'sleep'
        sleeper.write_text('#!/bin/bash\nexec /bin/sleep 0.1\n');sleeper.chmod(0o700)
    out=generate(profile,tmp_path/'out',password=PASSWORD)
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],COUNT_FILE=str(tmp_path/'count'),RC_FILE=str(tmp_path/'rc'),PATH_FILE=str(tmp_path/'path'))
    args=['--loop'] if loop else []
    child=pexpect.spawn(str(out/'keepalive.sh'),args,env=env,encoding='utf-8',timeout=15)
    child.expect('Пароль профиля:');child.sendline(PASSWORD)
    child.expect('UDP SPA sent')
    if loop:
        child.expect('UDP SPA sent')
        child.sendcontrol('c')
    child.expect(pexpect.EOF);child.close()
    assert child.exitstatus==(130 if loop else 0)
    assert len((tmp_path/'count').read_text().splitlines()) >= (2 if loop else 1)
    assert profile['key_base64'] in (tmp_path/'rc').read_text()
    assert not Path((tmp_path/'path').read_text()).exists()


def test_script_wrong_password_no_send(profile,tmp_path):
    import pexpect
    stub=tmp_path/'fwknop';stub.write_text('#!/bin/bash\ntouch "$SENT"\n');stub.chmod(0o700)
    out=generate(profile,tmp_path/'out',password=PASSWORD)
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],SENT=str(tmp_path/'sent'))
    child=pexpect.spawn(str(out/'keepalive.sh'),env=env,encoding='utf-8',timeout=15)
    child.expect('Пароль профиля:');child.sendline('wrong');child.expect(pexpect.EOF);child.close()
    assert child.exitstatus!=0 and not (tmp_path/'sent').exists()
    assert not list(tmp_path.glob('*.key'))


def test_script_unknown_flag(profile,tmp_path):
    out=generate(profile,tmp_path/'out')
    assert subprocess.run([str(out/'keepalive.sh'),'--bad'],capture_output=True).returncode==2

def test_encrypted_schema(profile):
    import jsonschema
    schema=json.loads((Path(__file__).resolve().parents[1]/'encrypted-profile.schema.json').read_text())
    jsonschema.Draft202012Validator(schema).validate(protect(profile,PASSWORD))

def test_password_limits(profile):
    for password in ['', 'я'*513, None]:
        with pytest.raises(ValueError):
            protect(profile,password)

def test_protected_script_requires_terminal(profile,tmp_path):
    stub=tmp_path/'fwknop';stub.write_text('#!/bin/bash\ntouch "$SENT"\n');stub.chmod(0o700)
    out=generate(profile,tmp_path/'out',password=PASSWORD)
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],SENT=str(tmp_path/'sent'))
    run=subprocess.run([str(out/'keepalive.sh')],env=env,input=PASSWORD,text=True,
                       capture_output=True,start_new_session=True,timeout=10)
    assert run.returncode!=0 and not (tmp_path/'sent').exists()
    assert PASSWORD not in run.stdout+run.stderr
