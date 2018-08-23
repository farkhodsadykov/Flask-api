from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response
from flask_wtf import FlaskForm, RecaptchaField
from flask_sqlalchemy  import SQLAlchemy
from uuid import uuid4
import uuid


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///DataBase/example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    first_name = db.Column(db.String(15))
    last_name = db.Column(db.String(15))
    user_name = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(15))


@app.route('/')
def index():

    users = User.query.all()

    return users
@app.route('/user/<public_id>', methods=['GET', 'POST'])
def user_info(public_id):
    data = request.get_json()
    if data:
        try:
            user = {}
            user['username'] =
            user['public_id'] = str(uuid.uuid4())
            user['first_name'] =
            user['last_name'] =
            user['email'] =
            user['password'] = hashed_password
            return jsonify({'User informations': user})

        except ValueError as error:
            return jsonify({'message': error})
    return jsonify({'message' : "missing public_id"})

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'missing username'})
    hashed_password = generate_password_hash(data['password'], method='sha256')
    if data:
        new_user = User(public_id=str(uuid.uuid4()), user_name=data['username'], first_name=data['firstname'], last_name=data['lastname'], email=data['email'])
@app.route('/api/signup', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}


if __name__ == "__main__":
    app.run(debug=True, port=8080, host='0.0.0.0')
