from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response
from flask_restful import Resource, Api
from flask_sqlalchemy  import SQLAlchemy
from functools import wraps
<<<<<<< HEAD
from uuid import uuid4
=======
import subprocess
import smtplib
>>>>>>> 1e65164aa3d00eab29f0a479052c61e3f8e48874
import uuid
import jwt
from uuid import uuid4
import datetime
app = Flask(__name__)
<<<<<<< HEAD
app.config['SECRET_KEY'] = '57644AC4CDAFC87E54731C8D249DE'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flaskuser:flask**@159.89.180.31/test'
=======

# Set up Main config
app.config['SECRET_KEY'] = 'qZjvXHxDv7Dcsv2a0IrmGZ5KNKZ10gO'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DataBase/flask_api.db'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcpbWAUAAAAAAHfKwXV_vDW3f5gP1ET0PHsvEOp'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcpbWAUAAAAABQidUSjPpv2K1AevKrTfSB9CYiN'
app.config['TESTING'] = True
>>>>>>> 1e65164aa3d00eab29f0a479052c61e3f8e48874
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


<<<<<<< HEAD
login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Tokeb is Invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


db = SQLAlchemy(app)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(60), unique=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    firstname = db.Column(db.String(20))
    lastname = db.Column(db.String(20))
    email = db.Column(db.String(30))
    status = db.Column(db.String(10))
    role = db.Column(db.String(10))
    group = db.Column(db.String(20))



@app.route('/', methods=['GET', 'POST'])
def index():
    data = request.get_json()
    return jsonify({'message': data})
    # return jsonify({ 'Meassage': 'Mising data' })


=======

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    message = db.Column(db.String(500))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    firstname = db.Column(db.String(15))
    lastname = db.Column(db.String(15))
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    status = db.Column(db.String(5))
    role = db.Column(db.String(5))


def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Tokeb is Invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/create_user', methods=['POST'])
@login_required_api
def craete_user(current_user):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), firstname=data['firstname'], lastname=data['lastname'], username=data['username'], email=data['email'], password=hashed_password, role='False' )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"response": "New user created!"})


@app.route('/user/<public_id>', methods=['GET'])
@login_required_api
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!" })
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['email'] = user.email
    user_data['username'] = user.username
    user_data['role'] = user.role
    return jsonify({'User': user_data})

@app.route('/user', methods=['GET'])
@login_required_api
def get_all_users(current_user):
    users = User.query.all()
    data = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['firstname'] = user.firstname
        user_data['lastname'] = user.lastname
        user_data['email'] = user.email
        user_data['username'] = user.username
        user_data['role'] = user.role
        data.append(user_data)
    return jsonify({'User': data})

@app.route('/user/<public_id>', methods=['PUT'])
@login_required_api
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!" })
    user.firstname = "Timur"
    db.session.commit()
    return jsonify({'message': 'user has been promoted!'})

@app.route("/login")
def login_api():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login-required"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minute=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login-required"'})

@app.route('/')
@login_required_api
def index(current_user):
    users = User.query.all()
    data = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['firstname'] = user.firstname
        user_data['lastname'] = user.lastname
        user_data['email'] = user.email
        user_data['username'] = user.username
        user_data['role'] = user.role
        data.append(user_data)
    return jsonify({'User': data})
>>>>>>> 1e65164aa3d00eab29f0a479052c61e3f8e48874

# Quering single user
@app.route('/user/<public_id>', methods=['GET'])
@login_required_api
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!" })
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['email'] = user.email
    user_data['username'] = user.username
    user_data['role'] = user.role
    user_data['group'] = user.group
    return jsonify({'User': user_data})


# Creating user
@app.route('/signup', methods=['GET', 'POST'])
def new_user():
    data = request.get_json()
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), password=hashed_password, username=data['username'], firstname=data['firstname'], lastname=data['lastname'],  email=data['email'], status=True, role='student', group='default')
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User has been created'})
    except Exception as e:
        return jsonify({'message': 'User already created'})
    return jsonify({ 'message': 'Mising data' })

<<<<<<< HEAD
if __name__ == "__main__":
    app.run(debug=True, port=8081, host='0.0.0.0')
=======
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
>>>>>>> 1e65164aa3d00eab29f0a479052c61e3f8e48874
