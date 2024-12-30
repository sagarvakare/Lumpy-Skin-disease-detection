import csv
import pickle
from flask import Flask, flash, redirect, render_template, request, url_for
import os
import classify
from PIL import Image
import numpy as np
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import LoginManager, login_user, UserMixin, logout_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
port = int(os.getenv('PORT', 5000))
class_names = ['Lumpy_Skin','Normal_Skin','No_Cow']


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SECRET_KEY'] = 'thisissecret'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    fname = db.Column(db.String(80), default='Unknown', nullable=False)
    lname = db.Column(db.String(80), default='Unknown', nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])   
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('uname')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect('/register')
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, username=username)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect('/output')
        else:
            return redirect('/login')
    return render_template('login.html')

@app.route('/', methods=['GET'])
def hello_world():
    return render_template("index.html")

@app.route('/model1')
def hello_world1():
    return render_template("model1.html")

# @app.route('/model2')
# def hello_world2():
#     return render_template("model2.html")

@app.route('/model2')
def hello_world3():
    return render_template("model2.html")

@app.route('/model3')
def hello_world4():
    return render_template("model3.html")

@app.route('/result')
def result():
    return render_template("result.html")

@app.route('/remedies')
def rrmedies():
    return render_template("remedies.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/dataset')
def dataset():
    return render_template("dataset.html")

@app.route('/output')
def output():
    return render_template("output.html")


@app.route('/home', methods=['GET',"POST"])
def home():
    if request.method=='POST':
        image_file = request.files["imagefile"]
        image_path = "./images/" + image_file.filename
        image = Image.open(image_file)
        prediction = classify.predict(image)
        result = " {} with a {:.2f}% Confidence.".format(class_names[np.argmax(prediction)], 100 * np.max(prediction))
    else:
        result=None
    return render_template("output.html", prediction=result)
    
if __name__ == '__main__':
    app.run(debug=True)
