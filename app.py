import requests
import json
from flask import Flask, render_template, request, url_for, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_migrate import Migrate
import os 
from waitress import serve
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm
import base64

# from bytebandits import get_pw

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
GEN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJqd3QtYXVkaWVuY2UiLCJpc3MiOiJodHRwczovL2p3dC1wcm92aWRlci1kb21haW4vIiwiY2xpZW50SWQiOiJzYW1wbGUiLCJ1c2VybmFtZSI6InByb2Z4dSIsInBheWluZyI6dHJ1ZSwiZXhwIjoxNzAyMDIyNTM3fQ.WLr6D9EvlmUfqlUFchb7g7G33KqToEB6KnM5sxr3iu4'

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(50), index=True, unique=True)
  email = db.Column(db.String(150), unique = True, index = True)
  password_hash = db.Column(db.String(150))
  joined_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)
  paying = db.Column(db.Integer)
  token = db.Column(db.String)

  def set_jwt(self, jwt):
      self.token = jwt
    
  def get_jwt(self):
      return self.token

  def set_password(self, password):
        self.password_hash = generate_password_hash(password)

  def check_password(self,password):
      return check_password_hash(self.password_hash,password)
  
  
  
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
  
  
  
###########################
#          ROUTES         #
###########################
  

@app.route('/index')
@app.route('/home')
# @login_required
def home():
    return render_template(
        "index.html"
    )


@app.route('/register', methods = ['POST','GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username =form.username.data, email = form.email.data, paying = form.paying.data)
  
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
        response = requests.post(HOST + '/jwt/', headers=headers, json=data)
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

    if current_user.is_authenticated:
         return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            session['jwt'] = user.get_jwt()
            return redirect(next or url_for('home'))
        flash('Invalid email address or password.')    
    return render_template('login.html', form=form)

@app.route('/password', methods=['GET', 'POST'])
def password():
    if request.method == 'POST':
        password_len = request.form['pw_len']
        digits = str(len(request.form.getlist('digits')) > 0)
        case = str(len(request.form.getlist('case')) > 0)
        specialChars = str(len(request.form.getlist('specialChars')) > 0)

        # SEND REQUEST TO API HERE 
        response = requests.get(HOST + '/password/Get' +
                               '/' + password_len + '/' + digits + '/' + case + '/' + specialChars)
        generated_password = response.content.decode('ASCII')

        context = dict(generated_password = generated_password)
        return render_template('password.html', **context)

@app.route('/storepassword', methods=['GET', 'POST'])
# @login_required
def store_password():
    if not current_user.is_authenticated:
         return redirect(url_for('login'))
    if request.method == 'POST':
        appName = request.form['appName'].lower()
        password = request.form['password'].encode('utf-8')
        bytepassword = base64.b64encode(password).decode('utf-8')
        filename = current_user.username + '_' + appName + '.txt'

        print(filename, current_user.username)
        headers = {
            'Authorization': 'Bearer ' + session['jwt'],
        }
        data = {
            'contents': bytepassword,
            'userID': current_user.username,
            'fileName': filename
        }

        # POST FILE TO STORAGE HERE 
        response = requests.post(HOST + '/storage/Submit/', headers=headers, json=data)
        store_success = response.content.decode('ASCII')

        context = dict(store_success = store_success, appName=appName)
        return render_template('storepassword.html', **context)
    
    return redirect(url_for('forbidden'))

@app.route('/retrievepassword', methods=['GET', 'POST'])
# @login_required
def retrievepassword():
    if not current_user.is_authenticated:
         return redirect(url_for('login'))
    if request.method == 'POST':
        appName = request.form['appName'].lower()
        filename = current_user.username + '_' + appName + '.txt'

        print(filename, current_user.username)

        headers = {
            'Authorization': 'Bearer  ' + session['jwt'],
        }

        # GET FILE FROM STORAGE HERE 
        response = requests.get(HOST + '/storage/Get/' + filename + '/'
                                + current_user.username + '/', headers=headers)
        
        found = False

        retrieved_password = ''
        if response.status_code == 200:
            retrieved_password = response.content.decode('ASCII')
            found = True

        context = dict(retrieved_password = retrieved_password, appName=appName, found=found)
        return render_template('getpassword.html', **context)
    return redirect(url_for('forbidden'))

@app.route("/forbidden",methods=['GET', 'POST'])
@login_required
def protected():
    return redirect(url_for('forbidden.html'))

@app.route('/premium')
def upload():
   return render_template('bugchecker.html')
	
@app.route('/viruscheck', methods = ['GET', 'POST'])
def viruscheck():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(url_for('upload'))
        f = request.files['file']
        if f.filename == '':
            return redirect(url_for('upload'))
        
        bytefile = base64.b64encode(f.read()).decode('utf-8')

        data = {
            'contents': bytefile, 
            'userID': current_user.username,
            'fileName': f.filename
        }

        response = requests.post(HOST + '/virusChecker/CheckFile/', json=data)
        
        print(response.status_code)

        res_text = response.content.decode('ASCII')
        res_text = res_text if res_text else 'API is offline. Please try again later!'
        context = {'res_text': res_text, 'filename': f.filename}

        return render_template('scannedfile.html', **context)
   
@app.route('/storefile', methods = ['GET', 'POST'])
def storefile():
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
        response = requests.post(HOST + '/storage/Submit/', headers=headers, json=data)
        store_success = response.content.decode('ASCII')

        context = dict(store_success = store_success, filename=f.filename)
        return render_template('storefile.html', **context)

@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
   if request.method == 'POST':
      f = request.files['file']
      f.save(secure_filename(f.filename))
      return 'file uploaded successfully'

@app.route("/logout")
# @login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    serve(app, host="0.0.0.0", port=8000)
    
