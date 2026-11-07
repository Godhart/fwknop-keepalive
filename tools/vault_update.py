"""Update only the two SPA secrets used by fwknop-spa-ansible 0.7.1."""
import base64
from contextlib import contextmanager
import io
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, TaggedScalar

FIELDS = {'key_base64': 'spa_key_base64', 'hmac_key_base64': 'spa_hmac_key_base64'}


def _run_vault(action, data, password_file, label=None):
    exe = shutil.which('ansible-vault')
    if not exe:
        raise ValueError('Установите ansible-core: команда ansible-vault не найдена')
    if not password_file:
        raise ValueError('Для шифрования нужен --vault-password-file')
    password_file = Path(password_file).expanduser().absolute()
    if not password_file.is_file():
        raise ValueError('Файл пароля Vault не найден')
    auth = ['--vault-password-file', str(password_file)]
    if label:
        auth = ['--vault-id', label + '@' + str(password_file)]
        if action == 'encrypt':
            auth += ['--encrypt-vault-id', label]
    # Input is stdin, output is stdout: decrypted YAML never goes to a disk file.
    try:
        result = subprocess.run([exe, action, '--output', '-', *auth], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Не удалось выполнить ansible-vault; исходный файл не изменён') from None
    if result.returncode:
        # Never forward Ansible diagnostics: they can contain plaintext YAML.
        raise ValueError('Ошибка ansible-vault: проверьте пароль и формат файла; исходный файл не изменён')
    if action == 'encrypt' and not result.stdout.startswith(b'$ANSIBLE_VAULT;'):
        raise ValueError('ansible-vault не вернул зашифрованный файл')
    return result.stdout


def _read(path):
    if path.is_symlink():
        raise ValueError('Символические ссылки для vault не поддерживаются')
    if not path.exists():
        return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError('Vault должен быть обычным файлом размером до 1 MiB')
    return path.read_bytes()


@contextmanager
def _lock(path):
    # Stable adjacent lock name serializes this utility; stale lock fails closed.
    lock = path.with_name(path.name + '.spa-update.lock')
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError('Vault заблокирован другой операцией; проверьте .spa-update.lock') from None
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)


def _private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def update_vault(profile, vault_path, *, password_file=None, encrypt=False, create=False):
    """Return {changed, encrypted, backup}. No key generation or server execution."""
    # This server project requires exactly 32 bytes for BOTH keys, unlike libfko.
    for source in FIELDS:
        try:
            raw = base64.b64decode(profile[source], validate=True)
        except (ValueError, KeyError, TypeError):
            raise ValueError('Некорректный ключ профиля') from None
        if len(raw) != 32 or base64.b64encode(raw).decode() != profile[source]:
            raise ValueError('fwknop-spa-ansible 0.7.1 требует оба ключа по 32 байта')
    if profile['key_base64'] == profile['hmac_key_base64']:
        raise ValueError('Ключи AES и HMAC должны отличаться')
    path = Path(vault_path).expanduser().absolute()
    with _lock(path):
        original = _read(path)
        if original is None and not create:
            raise ValueError('Vault не найден; используйте --create для создания')
        encrypted = original is not None and original.startswith(b'$ANSIBLE_VAULT;')
        label = None
        if encrypted:
            header = original.split(b'\n', 1)[0].decode('ascii')
            match = re.fullmatch(r'\$ANSIBLE_VAULT;1\.[12];AES256(?:;([A-Za-z0-9_.-]+))?', header)
            if not match:
                raise ValueError('Неподдерживаемый заголовок Ansible Vault')
            label = match.group(1)
            plain = _run_vault('decrypt', original, password_file, label)
        else:
            plain = original or b''
        yaml = YAML(typ='rt')
        yaml.preserve_quotes = True
        yaml.allow_duplicate_keys = False
        try:
            doc = yaml.load(plain.decode('utf-8'))
        except Exception:
            raise ValueError('Некорректный YAML в vault; содержимое не выводится') from None
        if doc is None:
            doc = CommentedMap()
        if not isinstance(doc, CommentedMap) or doc.merge:
            raise ValueError('Vault должен быть YAML mapping без merge-ключа в корне')
        for target in FIELDS.values():
            if target in doc and (isinstance(doc[target], TaggedScalar) or isinstance(doc[target], (dict, list))):
                raise ValueError('SPA-ключ должен быть строкой; inline !vault не заменяется открытым ключом. Используйте шифрование всего файла')
        will_encrypt = encrypted or encrypt
        if original is not None and all(doc.get(target) == profile[source] for source, target in FIELDS.items()) and encrypted == will_encrypt:
            return dict(changed=False, encrypted=encrypted, backup=None)
        for source, target in FIELDS.items():
            doc[target] = profile[source]
        out = io.StringIO()
        yaml.dump(doc, out)
        replacement = out.getvalue().encode('utf-8')
        if will_encrypt:
            replacement = _run_vault('encrypt', replacement, password_file, label)
        # Detect outside edits during decryption/encryption before writing.
        if _read(path) != original:
            raise ValueError('Vault изменён другим процессом; повторите операцию')
        backup = None
        if original is not None:
            backup = path.with_name(path.name + '.bak-' + uuid.uuid4().hex)
            _private_file(backup, original)
        fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(replacement)
                stream.flush()
                os.fsync(stream.fileno())
            if _read(path) != original:
                raise ValueError('Vault изменён другим процессом; замена отменена')
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return dict(changed=True, encrypted=will_encrypt, backup=str(backup) if backup else None)
