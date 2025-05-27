import random
import string

import sqlite3
from Crypto.Cipher import AES

con = sqlite3.connect("passwords.db")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS passwords(info, login, encrypted password, key, nonce)")


class Password:
    """
    A class to create and manage passwords

    This class provides methods to save in a database an ecrypted password and consult said database

    Attribute:
        password(str): the password to be managed
    """

    def __init__(self, info: str,  login: str, password: str):
        self.info = info
        self.login = login
        self.password = password
        self.key = self._generate_key(self)
        self.encrypted_password, self.nonce = self.encrypt()

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

    def save(self):
        """
        saves the encrypted password along with its encryption key and login
        :return:
        """
        cur.execute("""
        INSERT INTO passwords VALUES
        (?, ?, ?, ?, ?)""", (self.info, self.login, self.encrypted_password, self.key, self.nonce))
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


    def retrieve_password(self):
        res = cur.execute("""
        SELECT encrypted password, key, nonce
        FROM passwords
        WHERE info = ? AND login = ?""", (self.info, self.login))
        result = res.fetchone()
        if result:
            encrypted_password, key, nonce = result
            d_cipher = AES.new(key, AES.MODE_EAX, nonce)
            d_data = d_cipher.decrypt(encrypted_password)
            return d_data

    def initialize_deletion(self):
        """
        returns token for deletion confirmation
        :return:
        """
        pass

    def delete_password(self, token):
        """
        sqlite doesn't return errors so use rowcount to check if password exists
        syntax is DELETE FROM passwords
        WHERE search_condition;
        don't forget to commit

        use token to confirm deletion if token different, don't do it
        :return:
        """
        pass


    def delete_all_passwords(self, token):
        """
        uses also the token to confirm deletion

        syntax would be:
        DELETE FROM passwords
        don't forget to commit

        :param token:
        :return:
        """
        pass

if __name__ == "__main__":
    try:
        new_password = Password(info="newer_password", login="pass", password="bonjour")
        print(new_password.check())
        print(new_password.encrypted_password)
        # print(new_password.decrypted_password)
        new_password.save()
        print(new_password.retrieve_password())
    except Exception as e:
        print(f"an error has occured: {e}")
    finally:
        con.close()
