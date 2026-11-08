"""Host-build the same libfko and packet.c used by the Android JNI adapter."""
import ctypes as C
from pathlib import Path
import subprocess
import pytest
import socket
import os
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from spa_config import generate
from test_tools import profile

@pytest.fixture(scope='module', params=['android', 'ios'])
def lib(tmp_path_factory, request):
    root=Path(__file__).resolve().parents[1]/'android/app/src/main/cpp'
    so=tmp_path_factory.mktemp('native')/'libspa.so'
    config = Path(__file__).resolve().parents[1]/'ios/Native' if request.param == 'ios' else root
    files=list((root/'vendor/lib').glob('*.c'))+[root/'vendor/common'/f for f in ['fko_util.c','strlcpy.c','strlcat.c']]+[root/'packet.c']
    subprocess.run(['gcc','-shared','-fPIC','-DHAVE_CONFIG_H=1','-I'+str(config),'-I'+str(root),'-I'+str(root/'vendor/lib'),'-I'+str(root/'vendor/common'),*map(str,files),'-o',str(so)],check=True)
    lib=C.CDLL(str(so))
    lib.spa_packet.argtypes=[C.c_char_p,C.c_char_p,C.c_int,C.c_char_p,C.c_int,C.c_char_p,C.c_int,C.POINTER(C.c_void_p)]
    lib.fko_new_with_data.argtypes=[C.POINTER(C.c_void_p),C.c_char_p,C.c_char_p,C.c_int,C.c_int,C.c_char_p,C.c_int,C.c_int]
    lib.fko_destroy.argtypes=[C.c_void_p]
    for name in ['fko_get_spa_message','fko_get_username']:
        getattr(lib,name).argtypes=[C.c_void_p,C.POINTER(C.c_char_p)]
    lib.fko_get_spa_client_timeout.argtypes=[C.c_void_p,C.POINTER(C.c_int)]
    return lib

KEY=bytes(range(32)); HMAC=bytes(range(32,64))

def decode(lib,packet,hmac=HMAC):
    ctx=C.c_void_p()
    # fko.h: CBC=2; HMAC_SHA256=3.
    rc=lib.fko_new_with_data(C.byref(ctx),packet,KEY,len(KEY),2,hmac,len(hmac),3)
    if rc:
        if ctx:lib.fko_destroy(ctx)
        return rc,None
    try:
        msg=C.c_char_p();user=C.c_char_p();timeout=C.c_int()
        assert lib.fko_get_spa_message(ctx,C.byref(msg))==0
        assert lib.fko_get_username(ctx,C.byref(user))==0
        assert lib.fko_get_spa_client_timeout(ctx,C.byref(timeout))==0
        return 0,(msg.value,user.value,timeout.value)
    finally:lib.fko_destroy(ctx)

def test_roundtrip_and_tampering(lib):
    packets=[]
    libc=C.CDLL(None);libc.free.argtypes=[C.c_void_p]
    for _ in range(2):
        out=C.c_void_p()
        assert lib.spa_packet(b'0.0.0.0,tcp/22,tcp/443',b'mobile',300,KEY,32,HMAC,32,C.byref(out))==0
        packets.append(C.string_at(out));libc.free(out)
    assert packets[0]!=packets[1]
    assert decode(lib,packets[0])==(0,(b'0.0.0.0,tcp/22,tcp/443',b'mobile',300))
    bad=bytearray(packets[0]);bad[20]=ord('A') if bad[20]!=ord('A') else ord('B')
    assert decode(lib,bytes(bad))[0]!=0
    assert decode(lib,packets[0],b'x'*32)[0]!=0

def test_real_cli(lib,profile,tmp_path):
    cli=os.environ.get('FWKNOP_TEST_BINARY')
    if not cli:pytest.skip('Set FWKNOP_TEST_BINARY to test installed upstream fwknop client')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1',0));receiver.settimeout(5)
        profile['spa_port']=receiver.getsockname()[1]
        out=generate(profile,tmp_path/'out')
        (tmp_path/'fwknop').symlink_to(cli)
        env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'])
        result=subprocess.run([str(out/'keepalive.sh'),'--once'],env=env,capture_output=True,text=True,timeout=25)
        assert result.returncode==0,result.stderr
        packet,_=receiver.recvfrom(4096)
        assert decode(lib,packet)==(0,(b'0.0.0.0,tcp/22,tcp/443',b'mobile',300))
