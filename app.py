import requests
import json
from flask import Flask, render_template, request, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_migrate import Migrate
import os 
from waitress import serve
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm

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
HOST = 'http://34.23.37.33:31568/'

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
        data = {
            'username': form.username.data,
            'paying': form.paying.data
        }
        user_jwt = requests.post('http://ec2-107-22-87-117.compute-1.amazonaws.com:8080/', data)
        user.set_jwt(user_jwt)
       
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registration.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
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

@app.route("/forbidden",methods=['GET', 'POST'])
@login_required
def protected():
    return redirect(url_for('forbidden.html'))

@app.route('/upload')
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
        
        data = {
            'contents': f.read(),
            'userID': current_user.username,
            'fileName': f.filename
        }

        response = requests.post(HOST + '/virusChecker/CheckFile/', data)

        res_text = response.content.decode('ASCII')
        res_text = res_text if res_text else 'API is offline. Please try again later!'
        context = {'res_text': res_text, 'filename': f.filename}

        return render_template('scannedfile.html', **context)
   
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
    
