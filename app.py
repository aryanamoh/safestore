import os
from datetime import datetime
import base64
import requests
from flask import Flask, render_template, request, url_for, flash, redirect, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_migrate import Migrate
from waitress import serve
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm

###########################
#         INIT APP        #
###########################

app = Flask(__name__)

# initialize database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.app = app
migrate = Migrate(app, db)

# flask login session authentication
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

# init login manager
login_manager = LoginManager()
login_manager.init_app(app)

# Backend API connection
HOST = 'http://ec2-107-22-87-117.compute-1.amazonaws.com:8080'
# HOST ='http://localhost:8080'
GEN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJqd3QtYXVkaWVuY2UiLCJpc3MiOiJodHRwczovL2p3dC1wcm92aWRlci1kb21haW4vIiwiY2xpZW50SWQiOiJzYW1wbGUiLCJ1c2VybmFtZSI6InByb2Z4dSIsInBheWluZyI6dHJ1ZSwiZXhwIjoxNzAyMDIyNTM3fQ.WLr6D9EvlmUfqlUFchb7g7G33KqToEB6KnM5sxr3iu4'

# User Login management

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    email = db.Column(db.String(150), unique=True, index=True)
    password_hash = db.Column(db.String(150))
    joined_at = db.Column(db.DateTime(), default=datetime.utcnow, index=True)
    paying = db.Column(db.Integer)
    token = db.Column(db.String)

    def set_jwt(self, jwt):
        self.token = jwt

    def get_jwt(self):
        return self.token

    def set_password(self, new_password):
        self.password_hash = generate_password_hash(new_password)

    def check_password(self, input_password):
        return check_password_hash(self.password_hash, input_password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


###########################
#          ROUTES         #
###########################


@app.route('/index')
@app.route('/home')
def home():
    """
    Display the application homepage
    Returns:
        render index.html
    """
    
    return render_template(
        "index.html"
    )


@app.route('/register', methods=['POST', 'GET'])
def register():
    """
    Register new users in the Database
    Returns:
        render password.html
    """
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    email=form.email.data, paying=form.paying.data)

        # Request new JWT
        headers = {
            'Authorization': 'Bearer ' + GEN_TOKEN,
            'Content-Type': 'application/json',
        }

        paying = str(bool(int(form.paying.data))).lower()

        data = {
            'username': form.username.data,
            'paying': paying,
        }
        response = requests.post(HOST + '/jwt/', headers=headers, json=data, timeout=10)
        user_jwt = response.content.decode('ASCII')
        user.set_jwt(user_jwt)

        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registration.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page for registered users
    Returns:
        render login.html
    """

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get("next")
            session['jwt'] = user.get_jwt()
            return redirect(next_page or url_for('home'))
        flash('Invalid email address or password.')
    return render_template('login.html', form=form)


@app.route('/password', methods=['GET', 'POST'])
def password():
    """
    Generate a random password based on user-input parameters
    Returns:
        render password.html
    """
    
    if request.method == 'POST':
        password_len = request.form['pw_len']
        digits = str(len(request.form.getlist('digits')) > 0)
        case = str(len(request.form.getlist('case')) > 0)
        special_chars = str(len(request.form.getlist('specialChars')) > 0)

        # SEND REQUEST TO API HERE9
        response = requests.get(HOST + '/password/Get' +
                                '/' + password_len + '/' + digits + '/' + 
                                case + '/' + special_chars, timeout=10)
        generated_password = response.content.decode('ASCII')

        context = {'generated_password': generated_password}
        return render_template('password.html', **context)
    return redirect(url_for('forbidden'))


@app.route('/storepassword', methods=['GET', 'POST'])
def store_password():
    """
    Store user submitted password 
    Returns:
        render storepassword.html
    """
    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        app_name = request.form['appName'].lower()
        new_password = request.form['password'].encode('utf-8')
        bytepassword = base64.b64encode(new_password).decode('utf-8')
        filename = current_user.username + '_' + app_name + '.txt'

        headers = {
            'Authorization': 'Bearer ' + session['jwt'],
        }
        data = {
            'contents': bytepassword,
            'userID': current_user.username,
            'fileName': filename
        }

        # POST FILE TO STORAGE HERE
        response = requests.post(
            HOST + '/storage/Submit/', headers=headers, json=data, timeout=10)
        store_success = response.content.decode('ASCII')

        context = {"store_success": store_success, "appName": app_name}
        return render_template('storepassword.html', **context)

    return redirect(url_for('forbidden'))


@app.route('/retrievepassword', methods=['GET', 'POST'])
def retrievepassword():
    """
    Retrieve a stored password
    Returns:
        render getpassword.html
    """

    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        app_name = request.form['appName'].lower()
        filename = current_user.username + '_' + app_name + '.txt'

        headers = {
            'Authorization': 'Bearer  ' + session['jwt'],
        }

        # GET FILE FROM STORAGE HERE
        response = requests.get(HOST + '/storage/Get/' + filename + '/'
                                + current_user.username, headers=headers, timeout=10)

        found = False
        retrieved_password = ''
        if response.status_code == 200:
            retrieved_password = response.content.decode('ASCII')
            found = True

        context = {"retrieved_password": retrieved_password, "appName": app_name, "found": found,}
        return render_template('getpassword.html', **context)
    return redirect(url_for('forbidden'))


@app.route('/premium')
def premium():
    """
    Display the premium features page
    Returns:
        render bugchecker.html
    """

    return render_template('bugchecker.html')


@app.route('/viruscheck', methods=['GET', 'POST'])
def viruscheck():
    """
    Scan the uploaded file and display the results
    Returns:
        render scannedfile.html
    """

    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(url_for('upload'))
        f = request.files['file']
        if f.filename == '':
            return redirect(url_for('upload'))

        file = f.read()
        bytefile = base64.b64encode(file).decode('utf-8')

        data = {
            'contents': bytefile,
            'userID': current_user.username,
            'fileName': f.filename
        }

        response = requests.post(HOST + '/virusChecker/CheckFile/', json=data, timeout=10)

        res_text = response.content.decode('ASCII')
        res_text = res_text if res_text else 'API is offline. Please try again later!'
        is_virus = "delete immediately" in res_text
        context = {'res_text': res_text,
                   'filename': f.filename, 'is_virus': is_virus}

        return render_template('scannedfile.html', **context)
    return redirect(url_for('forbidden'))

@app.route('/download', methods=['GET', 'POST'])
def download():
    """
    Trigger download of the retrieved file
    Returns:
        file download
    """

    if request.method == 'POST':
        file_object = request.form['retrieved_file']
        byte_data = eval(file_object)
        filename = request.form['filename']

        with open(filename, 'wb') as file:
            file.write(byte_data)

        return send_file(
            filename,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename)

    return redirect(url_for('forbidden'))


@app.route('/retrievefile', methods=['GET', 'POST'])
def retrievefile():
    """
    Retrieve a stored file
    Returns:
        render getfile.html
    """
    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        filename = request.form['fileName']

        headers = {
            'Authorization': 'Bearer  ' + session['jwt'],
        }

        # GET FILE FROM STORAGE HERE
        response = requests.get(HOST + '/storage/Get/' + filename + '/'
                                + current_user.username, headers=headers, timeout=10)

        found = False
        retrieved_file = ''
        if response.status_code == 200:
            retrieved_file = response.content
            found = True

        context = dict(retrieved_file=retrieved_file,
                       filename=filename, found=found)
        return render_template('getfile.html', **context)
    return redirect(url_for('forbidden'))


@app.route('/storefile', methods=['GET', 'POST'])
def storefile():
    """
    Upload and securely store a file
    Returns:
        render storefile.html
    """
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(url_for('upload'))
        f = request.files['file']
        if f.filename == '':
            return redirect(url_for('upload'))

        bytefile = base64.b64encode(f.read()).decode('utf-8')

        headers = {
            'Authorization': 'Bearer ' + session['jwt'],
        }
        data = {
            'contents': bytefile,
            'userID': current_user.username,
            'fileName': f.filename,
        }

        # POST FILE TO STORAGE HERE
        response = requests.post(
            HOST + '/storage/Submit/', headers=headers, json=data, timeout=10)
        store_success = response.content.decode('ASCII')

        context = dict(store_success=store_success, filename=f.filename)
        return render_template('storefile.html', **context)
    return redirect(url_for('forbidden'))


@app.route("/forbidden", methods=['GET', 'POST'])
@login_required
def protected():
    """
    Forbidden
    Returns:
        render forbidden.html
    """

    return redirect(url_for('forbidden.html'))


@app.route("/logout")
def logout():
    """
    Log Out User
    Returns:
        render login.html
    """

    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    serve(app, host="0.0.0.0", port=8000)
