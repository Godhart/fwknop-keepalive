import base64
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from spa_config import generate_keys, with_new_keys
from vault_update import update_vault, _run_vault
from test_tools import profile

@pytest.mark.parametrize('key_len,hmac_len', [(16,32),(24,48),(32,64),(32,32)])
def test_key_sizes(key_len,hmac_len):
    a=generate_keys(key_len,hmac_len);b=generate_keys(key_len,hmac_len)
    assert len(base64.b64decode(a['key_base64']))==key_len
    assert len(base64.b64decode(a['hmac_key_base64']))==hmac_len
    assert a!=b and a['key_base64']!=a['hmac_key_base64']

@pytest.mark.parametrize('a,b', [(15,32),(33,32),(32,31),(32,65),(True,32),(32,32.0)])
def test_invalid_sizes(a,b):
    with pytest.raises(ValueError):generate_keys(a,b)

def test_profile_immutable(profile):
    updated=with_new_keys(profile)
    assert updated['key_base64']!=profile['key_base64']
    assert updated['server']==profile['server']

def test_plain_preserves(profile,tmp_path):
    p=tmp_path/'vault.yaml'
    original=b'# preserve comment\nspa_key_base64: old # encryption\nspa_hmac_key_base64: old2\nspa_acme_dns_credentials: |\n  token = KEEP\nother: "quoted"\n'
    p.write_bytes(original)
    result=update_vault(profile,p)
    doc=yaml.safe_load(p.read_text())
    assert doc['spa_key_base64']==profile['key_base64']
    assert doc['spa_hmac_key_base64']==profile['hmac_key_base64']
    assert doc['spa_acme_dns_credentials']=='token = KEEP\n'
    assert '# preserve comment' in p.read_text() and '# encryption' in p.read_text()
    assert 'other: "quoted"' in p.read_text()
    backup=Path(result['backup']);assert backup.read_bytes()==original
    assert p.stat().st_mode&0o777==0o600
    assert backup.stat().st_mode&0o777==0o600
    assert update_vault(profile,p)==dict(changed=False,encrypted=False,backup=None)
    assert len(list(tmp_path.glob('*.bak-*')))==1

def test_create_and_lengths(profile,tmp_path):
    p=tmp_path/'vault.yml'
    with pytest.raises(ValueError):update_vault(profile,p)
    result=update_vault(profile,p,create=True)
    assert result['changed'] and not result['backup']
    original=p.read_bytes()
    short=with_new_keys(profile,16,64)
    with pytest.raises(ValueError):update_vault(short,p)
    assert p.read_bytes()==original

@pytest.mark.parametrize('text',[
    'spa_key_base64: a\nspa_key_base64: b\n',
    '- not\n- mapping\n',
    'spa_key_base64: !vault |\n  ciphertext\n',
    'base: &base {x: y}\n<<: *base\n',
    'spa_key_base64: [wrong]\n',
])
def test_reject_without_changes(profile,tmp_path,text):
    p=tmp_path/'vault.yaml';p.write_text(text)
    with pytest.raises(ValueError):update_vault(profile,p)
    assert p.read_text()==text
    assert not list(tmp_path.glob('*.bak-*'))
    assert not list(tmp_path.glob('*.lock'))

def test_unrelated_inline_vault(profile,tmp_path):
    p=tmp_path/'vault.yaml'
    p.write_text('another_secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  abcdef\n')
    update_vault(profile,p)
    assert 'another_secret: !vault |' in p.read_text() and 'abcdef' in p.read_text()

def test_symlink(profile,tmp_path):
    p=tmp_path/'real';p.write_text('hello: world\n')
    link=tmp_path/'vault.yaml';link.symlink_to(p)
    with pytest.raises(ValueError):update_vault(profile,link)
    assert p.read_text()=='hello: world\n'

@pytest.mark.skipif(not shutil.which('ansible-vault'),reason='ansible-core required')
@pytest.mark.parametrize('label',[None,'prod'])
def test_encrypted_roundtrip(profile,tmp_path,label):
    password=tmp_path/'password';password.write_text('temporary-test-password\n');password.chmod(0o600)
    p=tmp_path/'vault.yaml'
    original=_run_vault('encrypt',b'# retain\nother: KEEP\n',password,label)
    p.write_bytes(original)
    result=update_vault(profile,p,password_file=password)
    assert p.read_bytes().startswith(b'$ANSIBLE_VAULT;')
    if label:assert b';prod\n' in p.read_bytes().split(b'\n')[0]+b'\n'
    assert profile['key_base64'].encode() not in p.read_bytes()
    plain=_run_vault('decrypt',p.read_bytes(),password,label)
    assert b'# retain' in plain and yaml.safe_load(plain)['other']=='KEEP'
    assert yaml.safe_load(plain)['spa_key_base64']==profile['key_base64']
    assert Path(result['backup']).read_bytes()==original
    assert update_vault(profile,p,password_file=password)['changed'] is False
    wrong=tmp_path/'wrong';wrong.write_text('incorrect\n')
    before=p.read_bytes()
    with pytest.raises(ValueError):update_vault(profile,p,password_file=wrong)
    assert p.read_bytes()==before
    with pytest.raises(ValueError):update_vault(profile,p)
    assert p.read_bytes()==before

@pytest.mark.skipif(not shutil.which('ansible-vault'),reason='ansible-core required')
def test_encrypt_new(profile,tmp_path):
    pw=tmp_path/'pw';pw.write_text('test-password\n')
    p=tmp_path/'vault.yaml'
    result=update_vault(profile,p,create=True,encrypt=True,password_file=pw)
    assert result['encrypted']
    assert yaml.safe_load(_run_vault('decrypt',p.read_bytes(),pw))['spa_hmac_key_base64']==profile['hmac_key_base64']
    assert sorted(x.name for x in tmp_path.iterdir())==['pw','vault.yaml']

def test_cli_new_and_rekey(tmp_path):
    cli=Path(__file__).resolve().parents[1]/'tools/spa_config.py'
    a=tmp_path/'a.yaml';b=tmp_path/'b.yaml'
    subprocess.run([sys.executable,str(cli),'new',str(a),'--key-bytes','24','--hmac-key-bytes','48'],check=True,capture_output=True)
    original=a.read_bytes()
    doc=yaml.safe_load(original)
    assert len(base64.b64decode(doc['key_base64']))==24
    assert len(base64.b64decode(doc['hmac_key_base64']))==48
    subprocess.run([sys.executable,str(cli),'rekey',str(a),'--out',str(b)],check=True,capture_output=True)
    assert a.read_bytes()==original
    new=yaml.safe_load(b.read_bytes());assert len(base64.b64decode(new['key_base64']))==32
    assert new['key_base64']!=doc['key_base64']
