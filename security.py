import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


_key = os.environ.get("CRED_ENC_KEY")

if not _key:
    raise RuntimeError("CRED_ENC_KEY environment variable not set")

fernet = Fernet(_key.encode())


def encrypt(text: str) -> bytes:
    if text is None:
        return None
    return fernet.encrypt(text.encode())


def decrypt(token: bytes) -> str:
    if token is None:
        return None
    return fernet.decrypt(token).decode()


