'''SPA Keepalive 0.2.0: validate YAML, generate offline QR and fwknop loop.'''
import argparse
import base64
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sys
import yaml
import jsonschema
import qrcode

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'profile.schema.json').read_text())

class UniqueLoader(yaml.SafeLoader):
    pass

def mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        k = loader.construct_object(key, deep=deep)
        if k in result:
            raise ValueError('Повторяющийся YAML ключ')
        result[k] = loader.construct_object(value, deep=deep)
    return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)

def validate(c):
    try:
        jsonschema.Draft202012Validator(SCHEMA).validate(c)
    except jsonschema.ValidationError as e:
        # Do not include e.message: it can disclose secret values.
        raise ValueError('Ошибка схемы: ' + '.'.join(map(str,e.absolute_path))) from None
    if c['allow_ip'] != 'source':
        ip = ipaddress.IPv4Address(c['allow_ip'])
        if ip.is_unspecified or ip.is_multicast or int(ip) == 0xffffffff:
            raise ValueError('allow_ip должен быть адресом клиента или source')
    for pair in c['access'].split(','):
        if not 1 <= int(pair.split('/')[1]) <= 65535:
            raise ValueError('Порт access вне диапазона')
    if c['interval_seconds'] >= c['access_timeout_seconds']:
        raise ValueError('Период должен быть меньше срока доступа')
    for name, lo, hi in [('key_base64',16,32),('hmac_key_base64',32,64)]:
        try:
            raw = base64.b64decode(c[name], validate=True)
            if not lo <= len(raw) <= hi or base64.b64encode(raw).decode() != c[name]:
                raise ValueError()
        except Exception:
            raise ValueError('Некорректный ключ: ' + name) from None
    if c['key_base64'] == c['hmac_key_base64']:
        raise ValueError('Используйте разные AES и HMAC ключи')
    return c

def load(path):
    if Path(path).stat().st_size > 8192:
        raise ValueError('Слишком большой файл профиля')
    return validate(yaml.load(Path(path).read_text(encoding='utf-8'), Loader=UniqueLoader))

def private_write(path, data, mode=0o600):
    # Exclusive create prevents overwriting another profile or following a symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)

def script(c):
    validate(c)
    fields = {
        'SPA_SERVER':c['server'], 'SPA_SERVER_PORT':c['spa_port'],
        'SPA_SERVER_PROTO':'udp', 'ACCESS':c['access'],
        'ALLOW_IP':'0.0.0.0' if c['allow_ip']=='source' else c['allow_ip'],
        'SPOOF_USER':c['username'], 'FW_TIMEOUT':c['access_timeout_seconds'],
        'KEY_BASE64':c['key_base64'], 'HMAC_KEY_BASE64':c['hmac_key_base64'],
        'USE_HMAC':'Y','HMAC_DIGEST_TYPE':'SHA256','DIGEST_TYPE':'SHA256',
        'ENCRYPTION_MODE':'CBC','SERVER_RESOLVE_IPV4':'Y'}
    rc = '[keepalive]\n' + '\n'.join(f'{k} {v}' for k,v in fields.items()) + '\n'
    return '''#!/usr/bin/env bash
# SPA Keepalive 0.2.0. Contains secrets: chmod 700; do not publish.
# Every iteration calls fwknop afresh (new timestamp, nonce and salt).
set -euo pipefail
umask 077
command -v fwknop >/dev/null || { echo "Install fwknop-client" >&2; exit 127; }
command -v timeout >/dev/null || { echo "Install coreutils" >&2; exit 127; }
command -v flock >/dev/null || { echo "Install util-linux" >&2; exit 127; }
# Prevent concurrent copies of this same script on Linux.
exec 9<"$0"
flock -n 9 || { echo "Already running" >&2; exit 1; }
work=$(mktemp -d)
child=""
cleanup() {
  if [[ -n "$child" ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cat >"$work/fwknoprc" <<'SPA_PRIVATE_CONFIG'
''' + rc + '''SPA_PRIVATE_CONFIG
while true; do
  # Keep rc secrets out of argv; --no-save-args avoids persisted invocation state.
  timeout --kill-after=2s 20s fwknop --rc-file "$work/fwknoprc" -n keepalive --no-save-args >/dev/null 2>&1 &
  child=$!
  rc=0
  if wait "$child"; then
    printf '%s UDP SPA sent (acceptance not confirmed)\\n' "$(date -Is)"
  else
    rc=$?
    printf '%s SPA send failed; retry next interval\\n' "$(date -Is)" >&2
  fi
  child=""
  if [[ "${1:-}" == "--once" ]]; then exit "$rc"; fi
  sleep ''' + str(c['interval_seconds']) + ''' &
  child=$!
  wait "$child"
  child=""
done
'''

def generate(c, out):
    validate(c)
    out = Path(out)
    # New directory only: no partial overwrite of existing credentials.
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    payload = json.dumps(c, ensure_ascii=False, separators=(',',':'))
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(payload); qr.make(fit=True)
    image = io.BytesIO(); qr.make_image().save(image, format='PNG')
    private_write(out/'profile.json', payload.encode())
    private_write(out/'profile-qr.png', image.getvalue())
    private_write(out/'keepalive.sh', script(c).encode(), 0o700)
    return out

def generate_keys(key_bytes=32, hmac_key_bytes=32):
    """Lengths are random secret bytes before Base64, not the AES cipher size."""
    if type(key_bytes) is not int or not 16 <= key_bytes <= 32:
        raise ValueError('key_bytes: целое число 16..32')
    if type(hmac_key_bytes) is not int or not 32 <= hmac_key_bytes <= 64:
        raise ValueError('hmac_key_bytes: целое число 32..64')
    return {
        'key_base64': base64.b64encode(secrets.token_bytes(key_bytes)).decode(),
        'hmac_key_base64': base64.b64encode(secrets.token_bytes(hmac_key_bytes)).decode(),
    }


def with_new_keys(config, key_bytes=32, hmac_key_bytes=32):
    config = dict(config)
    config.update(generate_keys(key_bytes, hmac_key_bytes))
    return validate(config)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    v = sub.add_parser('validate'); v.add_argument('profile')
    g = sub.add_parser('generate'); g.add_argument('profile'); g.add_argument('--out', required=True)
    n = sub.add_parser('new'); n.add_argument('profile', help='Новый YAML с новыми случайными ключами')
    k = sub.add_parser('rekey', help='Новые SPA-ключи; это НЕ смена пароля Ansible Vault')
    k.add_argument('profile'); k.add_argument('--out', required=True, help='Новый файл профиля; исходник сохраняется')
    for parser in (n, k):
        parser.add_argument('--key-bytes', type=int, default=32, help='16..32 случайных байта до Base64; по умолчанию 32')
        parser.add_argument('--hmac-key-bytes', type=int, default=32, help='32..64 случайных байта до Base64; по умолчанию 32')
    u = sub.add_parser('update-vault', help='Скопировать два ключа профиля в локальный Ansible vault')
    u.add_argument('profile'); u.add_argument('--vault', required=True)
    u.add_argument('--create', action='store_true', help='Разрешить создание отсутствующего vault')
    u.add_argument('--encrypt', action='store_true', help='Зашифровать новый или открытый YAML; зашифрованный остаётся зашифрованным всегда')
    u.add_argument('--vault-password-file', help='Файл пароля Ansible Vault; пароль не передаётся аргументом')
    args = p.parse_args()
    try:
        if args.cmd in ('new', 'rekey'):
            c = yaml.safe_load((ROOT/'profile.example.yaml').read_text()) if args.cmd == 'new' else load(args.profile)
            c = with_new_keys(c, args.key_bytes, args.hmac_key_bytes)
            dest = args.profile if args.cmd == 'new' else args.out
            private_write(dest, yaml.safe_dump(c,allow_unicode=True,sort_keys=False).encode())
            print('Создан профиль с новыми ключами. Согласуйте сервер; существующие QR и скрипты не обновлены.')
        else:
            c = load(args.profile)
            if args.cmd == 'generate':
                generate(c,args.out)
            elif args.cmd == 'update-vault':
                from vault_update import update_vault
                result = update_vault(c, args.vault, password_file=args.vault_password_file,
                                      encrypt=args.encrypt, create=args.create)
                print('Vault: ' + ('обновлён' if result['changed'] else 'без изменений'))
                print('Хранение: ' + ('Ansible Vault encryption' if result['encrypted'] else 'открытый YAML, права 0600 при записи'))
                if result['backup']: print('Резервная копия: ' + result['backup'])
            print('OK')
    except (ValueError, OSError, yaml.YAMLError) as e:
        print('Ошибка: '+ (str(e) if isinstance(e,ValueError) else type(e).__name__),file=sys.stderr)
        return 1
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
