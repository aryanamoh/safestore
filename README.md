# SafeStore

## About
SafeStore is an internet safety platform geared towards an elderly audience. With SafeStore, users can generate secure and random passwords. They can also easily store (and retrieve) them in the app. Premium users have access to our malware checker. Users upload their files and we report known instances of malware in the files. Premium users can also store their files in our secure, encrypted file storage.

SafeStore uses the ByteBandits service (found at: https://github.com/katyareichert/Byte-Bandits-ASWE) to provide these features to the user. The ByteBandits service provides endpoints for secure random password generation, malware checking, and encrypted file storage. Without the service, this client would have to pay for and maintain a larger database to hold client files (in addition to adding file encryption). The client would also have to design its own password generation functions and stay up to date with recommended algorithms (which the service takes care of).

The client, with help of the service, helps elderly individuals stay safer online by providing an easy interface to generate and store all passwords, encouraging unique passwords for each login. Similarly, the app provides a simple interface for checking files for malware.


## How to Run

### Activate virtual environment (Mac):
`source .venv/bin/activate`


### Install dependencies
`pip install -r requirements.txt`


### Run
Run the file app.py

For Mac users: in terminal, run `$python3 app.py`


## Credits

Style sheet adapted from [Glitch](https://glitch.com)

Login and registration logic adapted from Esther Vaati's <em>["A Detailed Guide to User Registration, Login, and Logout in Flask"](https://betterprogramming.pub/a-detailed-guide-to-user-registration-login-and-logout-in-flask-e86535665c07) <em>