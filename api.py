import random
import string

import sqlite3
from Crypto.Cipher import AES

con = sqlite3.connect("passwords.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS passwords(login, encrypted password, key, nonce)")

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
        self.key = self._generate_key(self)
        self.encrypted_password, self.nonce = self.encrypt()
        self.decrypted_password = self.decrypt()

    def check(self):
        """
        checks if the password is strong enough before encryption
        :param: the password you want to save
        :return: The Password's strength ('WEAK', 'FAIR' or 'STRONG')
        """
        if len(self.password) <= 8 or self.password.isdigit():
            return "WEAK"

        elif len(self.password) > 16 and self._is_special_character(self.password):
            return "STRONG"
        else:
            return "FAIR"

    @staticmethod
    def _is_special_character(self) -> bool:
        """
        Checks the password for at least one special character
        :param self:
        :return: True if there is at least one special character, returns False otherwise
        """
        special_character = "&'(-_)#{[|@]}!:;,?§%$"
        for character in self.password:
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
        cur.execute("""
        INSERT INTO passwords VALUES
        (?, ?, ?, ?)""", (self.login, self.encrypted_password, self.key, self.nonce))
        con.commit()

    @staticmethod
    def _generate_key(self) -> bytes:
        """
        generates a key to be used for AES
        :return key: the key to be used for encryption and decryption of the password
        """
        key = "".join((random.choices(string.ascii_letters + string.digits, k=16)))
        key = key.encode("utf-8")
        return key

    def encrypt(self):
        """
        encrypts the password using AES
        :return: the encrypted password
        """
        e_cipher = AES.new(self.key, AES.MODE_EAX)
        e_data = e_cipher.encrypt(self.password.encode("utf-8"))
        return e_data, e_cipher.nonce

    def decrypt(self):
        """
        decrypts the encrypted password using AES
        :return: the original password
        """
        d_cipher = AES.new(self.key, AES.MODE_EAX, self.nonce)
        d_data = d_cipher.decrypt(self.encrypted_password)
        return d_data

if __name__ == "__main__":
    new_password = Password(login="admin", password="bonjour")
    print(new_password.check())
    print(new_password.encrypted_password)
    print(new_password.decrypted_password)
    new_password.save()
