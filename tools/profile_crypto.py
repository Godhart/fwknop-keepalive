"""Portable encrypted profile v2. Also embedded verbatim in generated scripts."""
import base64
import hashlib
import json
import secrets

AAD = b'fwknop-keepalive/profile/v2'
ITERATIONS = 600000
FIELDS = {'version', 'format', 'kdf', 'iterations', 'salt', 'nonce', 'ciphertext'}


def is_encrypted(value):
    return isinstance(value, dict) and value.get('version') == 2


def _b64(value, size=None):
    if not isinstance(value, str):
        raise ValueError('Invalid encrypted profile')
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode() != value or (size is not None and len(raw) != size):
        raise ValueError('Invalid encrypted profile')
    return raw


def check_envelope(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or type(value['version']) is not int
        or value['version'] != 2 or value['format'] != 'spa-profile-aes256-gcm'
        or value['kdf'] != 'pbkdf2-sha256' or type(value['iterations']) is not int
        or value['iterations'] != ITERATIONS):
        raise ValueError('Unsupported encrypted profile')
    _b64(value['salt'], 16); _b64(value['nonce'], 12)
    if not 17 <= len(_b64(value['ciphertext'])) <= 8192:
        raise ValueError('Invalid encrypted profile size')
    return value


def _password_bytes(password):
    if not isinstance(password, str) or not password or len(password.encode('utf-8')) > 1024:
        raise ValueError('Password must contain 1..1024 UTF-8 bytes')
    return password.encode('utf-8')


def protect(profile, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = secrets.token_bytes(16); nonce = secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac('sha256', _password_bytes(password), salt, ITERATIONS, 32)
    plain = json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    data = AESGCM(key).encrypt(nonce, plain, AAD)
    return dict(version=2, format='spa-profile-aes256-gcm', kdf='pbkdf2-sha256',
                iterations=ITERATIONS, salt=base64.b64encode(salt).decode(),
                nonce=base64.b64encode(nonce).decode(), ciphertext=base64.b64encode(data).decode())


def unlock(envelope, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    check_envelope(envelope)
    key = hashlib.pbkdf2_hmac('sha256', _password_bytes(password), _b64(envelope['salt']), ITERATIONS, 32)
    try:
        plain = AESGCM(key).decrypt(_b64(envelope['nonce']), _b64(envelope['ciphertext']), AAD)
        result = json.loads(plain.decode('utf-8'))
    except (InvalidTag, UnicodeError, json.JSONDecodeError):
        raise ValueError('Неверный пароль или повреждённый профиль') from None
    if not isinstance(result, dict) or result.get('version') != 1:
        raise ValueError('Invalid inner profile')
    return result


def ask_password(confirm=False):
    import getpass
    import warnings
    # No fallback to echoed stdin when running from a pipe or CI.
    try:
        with open('/dev/tty', 'w') as tty, warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Пароль профиля: ', stream=tty)
            _password_bytes(value)
            if confirm and value != getpass.getpass('Повторите пароль: ', stream=tty):
                raise ValueError('Пароли не совпадают')
            return value
    except (OSError, getpass.GetPassWarning):
        raise ValueError('Для ввода пароля нужен интерактивный терминал') from None
