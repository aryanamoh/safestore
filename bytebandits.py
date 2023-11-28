from dotenv import load_dotenv
from pprint import pprint
import requests
import os

load_dotenv()

def get_pw(length=12, digits=True, case=True, specialChars=True):
    '''generate password from api'''

    request_url = f'http://0.0.0.0:8080/password/Get/{length}/{digits}/{case}/{specialChars}'
    password = requests.get(request_url).json()

    return password

if __name__ == "__main__":
    print('\n*** Get Password *** \n')

    length = input("\n Enter password length: ")

    digits = input("\n Should the password include digits? (y/n): ")
    if digits.lower() == 'y':
        digits = True
    else:
        digits = False

    case = input("\n Uppercase? (y/n): ")
    if case.lower() == 'y':
        case = True
    else:
        case = False

    specialChars = input("\n Special characters? (y/n): ")
    if specialChars.lower() == 'y':
        specialChars = True
    else:
        specialChars = False

    password = get_pw(length, digits, case, specialChars)