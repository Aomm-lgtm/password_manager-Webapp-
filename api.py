import random
import string
import sqlite3

class Password:
    """
    A class to create and manage passwords

    This class provides method to save in a database an ecrypted password and consult said database

    Attribute:
        password(str): the password to be managed
    """

    def __init__(self, password_name: str, password: str):
        self.password_name = password_name
        self.password = password
        self.key = self.generate_key()
        self.encrypted_password = self.encrypt(self.password, self.key)



    def checkstrength(self, password):
        if password.isdigit() or len(password) < 8:
            return "WEAK"
        elif 8 <= len(password) <= 16:
            return "FAIR"
        elif len(password) > 16 and _is_special_character(password):
            return "STRONG"
        else:
            return "FAIR"

    def _is_special_character(self, password) -> bool:
        special_characters = "!@#$%^&*()-+?_=,<>;:/"
        for character in password:
            if character in special_characters:
                return True
        return False

    def generate_key(self):
        length = random.randint(8, 12)
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        int_key = ""
        for character in key:
            int_key += str(ord(character))

        int_key = int(int_key) % 255
        return int_key

    def encrypt(self, password, key):
        encpassword = ""
        for character in password:
            enccharacter = chr(ord(character) + key)
            encpassword = encpassword + enccharacter

        return encpassword, key

    def decryption(self, encpassword, key):
        decpassword = ""
        for character in encpassword:
            deccharacter = chr(ord(character) - key)
            decpassword = decpassword + deccharacter

        return decpassword

