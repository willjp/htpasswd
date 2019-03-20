from builtins import object
from htpasswd.hashtypes import hash_bcrypt
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


class UserExists(Exception):

    def __str__(self):
        return "User already exists"


class UserNotExists(Exception):

    def __str__(self):
        return "User not exists"


class UnknownEncryptionMode(Exception):

    def __init__(self, mode):
        self.mode = mode

    def __str__(self):
        return "Encryption Mode %s is unknown/unsupported" % self.mode


class Basic(object):

    """ Basic object deals with Basic HTTP Authorization configuration file.
    It is passed the path to userdb file. """

    def __init__(self, userdb, hashtype=None):
        # defaults to bcrypt, because cross-platform
        if hashtype is None:
            hashtype = hash_bcrypt
        self.hashtype = hashtype
        self.userdb = userdb
        self.initial_users = OrderedDict()
        self.new_users = OrderedDict()

    def __enter__(self):
        with open(self.userdb, "r") as users:
            for i in users:
                line = i.strip()
                if not line:
                    continue
                user, password = i.split(":", 1)
                self.initial_users[user] = password
        self.new_users = self.initial_users.copy()
        return self

    def __exit__(self, type, value, traceback):
        if self.new_users == self.initial_users:
            return
        with open(self.userdb, "w") as userdb:
            for user in self.new_users:
                userdb.write("%s:%s" % (user, self.new_users[user]))

    def __contains__(self, user):
        return user in self.users

    @property
    def users(self):
        """ Returns users in a tuple """
        return list(self.new_users.keys())

    def add(self, user, password):
        """ Adds a user with password """
        if self.__contains__(user):
            raise UserExists
        self.new_users[user] = self._encrypt_password(password) + "\n"

    def pop(self, user):
        """ Deletes a user """
        if not self.__contains__(user):
            raise UserNotExists
        self.new_users.pop(user)

    def change_password(self, user, password):
        """ Changes user password """
        if not self.__contains__(user):
            raise UserNotExists
        self.new_users[user] = self._encrypt_password(password) + "\n"

    def _encrypt_password(self, password):
        """encrypt the password for given mode """
        return self.hashtype.hash_password(password)
