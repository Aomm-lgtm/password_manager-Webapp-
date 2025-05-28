import secrets
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
        self.deletion_token = None
        self.pending_deletion = False


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
        alphabet = string.ascii_letters + string.digits
        key = ''.join(secrets.choice(alphabet) for i in range (16))
        return key.encode('utf-8')

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

    @staticmethod
    def initialize_deletion():
        """
        creates and returns a token to confirm deletion
        :return: token that needs to be inputed to confirm deletion
        """
        alphabet = string.ascii_letters + string.digits
        del_token = ''.join(secrets.choice(alphabet) for i in range(16))
        pending_del = True
        return del_token, pending_del

    @staticmethod
    def delete_password(token: str, pending_del: bool, info: str, login: str):
        """
        sqlite doesn't return errors so use rowcount to check if password exists
        syntax is DELETE FROM passwords
        WHERE search_condition;
        don't forget to commit

        use token to confirm deletion if token different, don't do it
        :return:
        """
        if pending_del and token == Password.initialize_deletion()[0] :

            cur.execute("""
            DELETE FROM passwords
            WHERE info = ? AND login = ?""", (info, login))
            if cur.rowcount == 0:
                print("No password with that ID was found")
            else:
                print(f"The password related to the ID: info = {info}, login = {login} has been deleted. ")

            con.commit()

        else:
            print("Mismatched token or no pending deletion, the password will not be deleted")

    @staticmethod
    def delete_all_passwords(token, pending_del):
        """
        uses also the token to confirm deletion

        syntax would be:
        DELETE FROM passwords
        don't forget to commit

        :param token:
        :return:
        """
        if pending_del and token == Password.initialize_deletion()[0]:

            cur.execute("""
            DELETE FROM passwords""")
            if cur.rowcount == 0:
                print("No passwords were found in the database")
            else:
                print("The passwords were deleted from the database")

            con.commit()

        else:
            print("Mismatched token or no pending deletion, the passwords will not be deleted")

if __name__ == "__main__":
    try:
        newer_password = Password(info="very new", login="yes", password="hola")
        print(newer_password.check())
        print(newer_password.encrypted_password)
        # print(new_password.decrypted_password)
        newer_password.save()
        print(newer_password.retrieve_password())
        deletion_token, pending_deletion = Password.initialize_deletion()
        print(deletion_token)
        # Password.delete_password(deletion_token, pending_deletion, newer_password.info, newer_password.login)

    except Exception as e:
        print(f"an error has occured: {e}")
    finally:
        con.close()
        pending_deletion = False
