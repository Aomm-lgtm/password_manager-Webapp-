import sqlite3



# make the password class
# it creates the password object which creates login, encpassword, key
# also has exits, save, delete, delete all functions

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
        # self.key = self._generate_key(self)
        # self.encrypted_password = self.encrypt(self)


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

    def save(self, ):
        """
        saves the encrypted password along with its encryption key and login
        :return:
        """
        pass

    def _generate_key(self):
        """
        generates a key to be used for AES
        :return:
        """
        pass

    def encrypt(self):
        """encrypts the password"""
        pass

    def decrypt(self):
        pass

if __name__ == "__main__":
    new_password = Password(login= "admin", password= "122345678903456783")
    print(new_password.check(new_password.password))