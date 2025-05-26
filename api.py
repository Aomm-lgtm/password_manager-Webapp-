import random
import string

import sqlite3
from Crypto.Cipher import AES

# con = sqlite3.connect("passwords.db")
# cur = con.cursor()
# cur.execute("CREATE TABLE passwords(login, encrypted password", "key")

class Password:
    """
    A class to create and manage passwords

    This class provides method to save in a database an ecrypted password and consult said database

    Attribute:
        password(str): the password to be managed
    """

    def __init__(self, login: str, password: str):
        self.login = login
        self.password = password
        self.key = self._generate_key()
        self.encrypted_password, self.e_cipher = self.encrypt()
        self.decrypted_password = self.decrypt()

    def check(self, password):
        """
        checks if the password is strong enough before encryption
        :param password: the password you want to save
        :return:
        """
        if len(password) <= 8 or password.isdigit():
            return "WEAK"

        elif len(password) > 16 and self._is_special_character(password):
            return "STRONG"
        else:
            return "FAIR"

    @staticmethod
    def _is_special_character(self, password):
        special_character = "&'(-_)#{[|@]}!:;,?§%$"
        for character in password:
            if character in special_character:
                return True
            return False

    def exist(self, login):
        """
        determines if the password exists
        :param login:
        :return:
        """
        pass

    def save(self):
        """
        saves the encrypted password along with its encryption key and login
        :return:
        """
        pass

    @staticmethod
    def _generate_key(self):
        """
        generates a key to be used for AES
        :return:
        """
        key = "".join((random.choices(string.ascii_letters + string.digits, k=16)))
        return key.encode("utf-8")

    def encrypt(self):
        """encrypts the password"""
        e_cipher = AES.new(self.key, AES.MODE_EAX)
        e_data = e_cipher.encrypt(self.password.encode("utf-8"))
        return e_data, e_cipher

    def decrypt(self):
        d_cipher = AES.new(self.key, AES.MODE_EAX, self.e_cipher.nonce)
        d_data = d_cipher.decrypt(self.encrypted_password)
        return d_data


if __name__ == "__main__":
    new_password = Password(login="admin", password="bonjour")
    print(new_password.check(new_password.password))
    print(new_password.encrypted_password)
    print(new_password.decrypted_password)
