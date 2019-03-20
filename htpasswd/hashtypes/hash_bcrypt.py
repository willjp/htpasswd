import bcrypt


def generate_salt(**kwargs):
    salt = bcrypt.gensalt(**kwargs)
    return salt


def hash_password(password, salt=None):
    """ Crypts password using bcrypt module.

    Args:
        password (str):
            plaintext password you'd like salt/hash
        **kwargs:
            additional keyword arguments can be passed to
            :py:mod:`bcrypt.gensalt`

    Returns:
        str: unicode string containing salted/hashed password.
    """

    if salt is None:
        salt = generate_salt()

    hashpw = bcrypt.hashpw(password.encode('utf-8'), salt)
    hashpw_unicode = hashpw.decode('utf-8')
    return hashpw_unicode


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
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
