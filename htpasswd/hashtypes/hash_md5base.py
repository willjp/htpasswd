import subprocess
from htpasswd.hashutils import opensslutils

_algorithm = '1'


def generate_salt():
    return opensslutils.generate_salt()


def hash_password(password, salt=None):
    return opensslutils.hash_password(_algorithm, password, salt)


def check_password(password, password_hash):
    return opensslutils.check_password(_algorithm, password, password_hash)
