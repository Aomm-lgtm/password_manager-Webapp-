# Password Manager

A command line application password manager simulation.

About the files:
Only password_manager.py and passwords.json are required. The others are certain isolated functions when I was just working on them.

## commands are:

### save
### get password
### delete 
### delete all 

## Most basic features 
[x] can encrypt a password using the most basic encryption <br />
[x] can save an encrypted password<br />
[x] can retrieve and decryt a saved password<br />
[x] can delete a password in particular<br />
[x] can delete all passwords<br />

## More features

[x] can tell a password's strength and prevent a user from using a weak password<br />
[x] can generate passwords for the user<br />
[] storing the password elsewhere ?<br />
[x] more sophisticated encryption <br />
[x] ask for permission before deletion


## Currently known bugs
[x] if two passwords have the same save name, the first will me overwritten by the second<br />
[x] when asked if the user wants to continue with a vulnerable password, saying no just asks the question again instead of asking for a different password<br />

## save
This command follows multiple steps :

- The app asks the user for : the password name, the password itself and the password key
- The password's strength is assessed, if it is deemed too vulnerable, the user will be made aware of it
- The password is encrypted using a ceasar cipher like function called _encryption, it uses a randomly generated interger key to shift the characters ord
- The name, key and encrypted password are stored in a json file

## get password
Asks for the password, retrieves it and the key (if not in file, says so), decrypts the password, displays it

## delete
Asks for the password, searches it, if it exists in the file pops it and overwrites the file. If it doesn't exist says so 

## delete all
Asks for confirmation and then overwrites the json file

