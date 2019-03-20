import crypt
import string
import random


def generate_salt():
    """ Generates some salt """
    symbols = string.ascii_letters + string.digits
    return random.choice(symbols) + random.choice(symbols)


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
        return crypt.crypt(password)
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
    return crypt.crypt(password, password_hash) == password_hash
