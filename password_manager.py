import json
import random
import string

import typer
from rich.prompt import Confirm

strength_style = {
    "STRONG": "[bold green]STRONG[/bold green]",
    "FAIR": "[bold yellow]FAIR[/bold yellow]",
    "WEAK": "[bold red]WEAK[/bold red]",
}

app = typer.Typer()



@app.command("save")
def save():
    """
    encrypts your password using a randomly generated key and then saves it in a json file
    """

    while True:
        save_name = typer.prompt("Please enter a save name to be associated to your password")  
        with open("passwords.json", 'r') as f:
            data = json.load(f)
            if save_name in data:
                typer.echo("This name is already taken, plesae try a new one")
                continue

        while True:

                key = _make_key()
            
                while True:
                    password = typer.prompt("Please enter your password")
                    strength = _check_strength(password)
                    if strength != "STRONG" and Confirm.ask(f"""Your password is {strength_style[strength]}, to be {strength_style['STRONG']} it should contain at least 16 character (letters, numbers and special characters).\nAre you sure you wish to use it?"""):
                
                        password = _encrypt(password, key)
                        with open('passwords.json', 'r') as f:
                            data = json.load(f)

                            data[save_name] = {
                            "save name": save_name,
                            "key": key,
                            "password": password[0]
                            }   

                        with open('passwords.json', 'w') as f:
                            json.dump(data, f, indent=6)
    
                    break
        
                break
        
        break


@app.command("get_password")
def get_password():
    """
    asks for your password and decrypts it
    """
    password_to_get = typer.prompt("What password do you want to see?")

    with open('passwords.json', "r") as f:
        data = json.load(f)
        if password_to_get in data:
            encpassword = data[password_to_get]["password"]
            key = data[password_to_get]["key"]

            password = _decrypt(encpassword, key)
            typer.echo(f"The password is: {password}")


@app.command("delete")
def delete():
    """
    deletes the desired password from the json file
    """
    password_to_delete = typer.prompt("What password do you want to delete?")
    while True:
        if Confirm.ask(f"Are you sure you wish to delete: {password_to_delete}?"):

            with open('passwords.json', "r") as f:
                data = json.load(f)
                if password_to_delete in data:
                    data.pop(password_to_delete)

                    with open('passwords.json', "w") as f:
                        json.dump(data, f, indent=6)
    
                    typer.echo(f"Password: '{password_to_delete}' deleted")

                else:
                    typer.echo("No passwords are saved under this name")

        typer.echo(f"Password: {password_to_delete} will not be deleted")
        break
        

@app.command("delete_all")
def delete_all():
    """
    deletes all passwords in the json file
    """
    if Confirm.ask("Are you sure you wish to delete all your saved passwords?"):

        with open('passwords.json',"w") as f:
            json.dump({}, f)

            typer.echo("All your passwords have been deleted")

    else:
        typer.echo("Your passwords will not be deleted")


def _check_strength(password: str) -> str:
    """
    checks your passwords strength and assigns a level to it (WEAK, FAIR, STRONG)

    Args:
        password: the password you want to be assessed

    Returns:
        strength: your password strength, can either be WEAK, FAIR or STRONG.
    """

    if password.isdigit() or len(password) < 8:
        return "WEAK"
    elif 8<= len(password) <= 16:
            return "FAIR"
    elif len(password) > 16 and _is_special_character(password):
        return "STRONG"
    else:
        return "FAIR"


def _is_special_character(password: str) -> bool :
    """
    checks if the password contains at leats one special character

    Args:
        password: the password you want to be assessed

    Returns:
        bool: True if there is at least one special character, False otherwise
    """
    special_characters = "!@#$%^&*()-+?_=,<>;:/"
    for character in password:
        if character in special_characters:
            return True
    return False


def _make_key() -> int:
    """
    uses random and string modules to generate a random string (8 to 12 characters long) to be used in _encryption function as a key

    Returns:
        key: the key that will be used to encryot
    """

    length = random.randint(8, 12)
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    int_key = ""
    for character in key:
        int_key += str(ord(character))

    int_key = int(int_key)%255
    return int_key
        

def _encrypt(password: str, key: int) -> tuple[str, int]:
    """
    Basic, ceasar cipher like encrypt function

    Args:
        password: password you wish to encrypt
        key: the key to encrypt and decrypt the password (shifts the characters)

    Returns:
        encpassword: your now encrypted password
        key: the key to encrypt and decrypt the password
    """
    encpassword = ""
    for character in password:
        enccharacter = chr(ord(character)+key)
        encpassword = encpassword + enccharacter
    
    return encpassword, key


def _decrypt(encpassword: str, key: int) -> str:
    """
    Basic, ceasar cipher like decrypt function 

    Args:
        encpassword: the returned password of the _encrypt function
        key: the returned key of the _encrypt function

    Returns:
        decpassword: your original password
    """
    decpassword = ""
    for character in encpassword:
        deccharacter = chr(ord(character) - key)
        decpassword = decpassword + deccharacter
    
    return decpassword


if __name__ == "__main__":
    app()
