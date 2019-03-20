import string
import subprocess


def generate_salt():
    """ Generates some salt. (unecessary, openssl handles for you) """
    symbols = string.ascii_letters + string.digits
    return random.choice(symbols) + random.choice(symbols)


def hash_password(algorithm, password, salt=None):
    """ Crypts password (unix only).

    Args:
        algorithm (str): ``(ex: 'apr1', '1', 'crypt')``
            One of the ``openssl passwd`` algorithm choices.

        password (str):
            plaintext password you'd like salt/hash

        salt (str, optional):
            optionally, you may provide your own password salt.

    Returns:
        str: unicode string containing salted/hashed password.
    """
    # openssl passwd algorithm choice
    if not algorithm.startswith('-'):
        algorithm = '-{}'.format(algorithm)

    # commandline command
    cmds = ['openssl', 'passwd', algorithm]
    if salt is not None:
        cmds.extend(['-salt', salt])
    cmds.append(password)

    # get result
    result = subprocess.check_output(cmds)
    password_hash = result.decode('utf-8').strip()
    return password_hash


def check_password(algorithm, password, password_hash):
    """ Confirms password matches hash.

    Args:
        algorithm (str): ``(ex: 'apr1', '1', 'crypt' )``
            One of the ``openssl passwd`` algorithm choices.

        password (str):
            plaintext password

        password_hash (str):
            hash of the password you are validating against

    Returns:
        bool: True/False does password match hash
    """
    # strip leading '-' from algorithm if present
    if algorithm.startswith('-'):
        algorithm = algorithm[1:]

    # validate that password hash is using same algorithm
    (_, hash_algorithm, hash_salt, hash_pw) = password_hash.split('$')
    if algorithm != hash_algorithm:
        raise TypeError('password hash was hashed with a different algorithm')

    # compare passwords
    compare_hash = hash_password(algorithm, password, salt=hash_salt)
    return compare_hash == password_hash
