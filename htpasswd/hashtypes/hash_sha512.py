#!/usr/bin/env python
import sys
if sys.version_info[:2] < (3, 3):
    raise NotImplementedError('crypt methods introduced in python-3.3')
import crypt
_crypt_method = crypt.METHOD_SHA512


def generate_salt(rounds=None):
    """ Generates some salt """
    kwargs = {}
    if rounds is not None:
        kwargs = {'rounds': rounds}

    salt = crypt.mksalt(_crypt_method, **kwargs)
    return salt


def hash_password(password, salt=None):
    """ Crypts password (unix only).

    Args:
        password (str):
            plaintext password you'd like salt/hash

        salt (str, optional):
            optionally, you may provide your own password salt.

    Returns:
        str: unicode string containing salted/hashed password.
    """
    if salt is None:
        return crypt.crypt(password, generate_salt())
    else:
        return crypt.crypt(password, salt)


def check_password(password, password_hash):
    """ Confirms password matches hash.

    Args:
        password (str):
            plaintext password
        password_hash (str):
            hash of the password you are validating against

    Returns:
        bool: True/False does password match hash
    """
    (_, algorithm, salt, _) = password_hash.split('$')
    gensalt = '${}${}'.format(algorithm, salt)

    compare_hash = crypt.crypt(password, gensalt)
    return compare_hash == password_hash
