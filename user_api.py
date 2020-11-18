
import os
import markdown as markdown
from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from secrets import token_hex,token_bytes
from functools import wraps
import jwt
import datetime
import bcrypt
import hashlib

import logging
from logging.handlers import RotatingFileHandler
# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = '07257fa02fcee4993a3d5c3884adb18327810e87abbb5208f3c71bb6b58fcf3a' # Generated from Cryptographically Secure Pseudo-Random Number Generators (CSPRNG)<-> secrets()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True


db = SQLAlchemy(app)






class User(db.Model):
    __tablename__ = 'users' # Rows of the table users should be mapped to this class
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    hash_pass = db.Column(db.String(70))
    salt_pass = db.Column(db.String(70)) # Salt for securely storing password
    firstName_lastName = db.Column(db.String(100))
    fav_search_engine = db.Column(db.String(50))
    logged_in_state = db.Column(db.Integer)

    # needs to be re-implementeed
    def hash_password(self, password,salt):
        self.hash_pass=hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 10000) # NIST Standards are Followed
        # salt = bcrypt.gensalt(rounds=12)
        # self.hash_pass = bcrypt.hashpw(password.encode(), salt)

    def verify_password(self, password):
        print(self.salt_pass)
        check_hash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), self.salt_pass, 10000)
        if check_hash == self.hash_pass:  # Returns true if both calculated hash and the saved are same ; Returns False if they are different
            return True
        else:
            #ADD Log functionality
            app.logger.error('%s  : Failed login attempt of user with user_id: %d ', str(datetime.datetime.now()) ,self.id)
            return False
        # return bcrypt.checkpw(password.encode(), self.hash_pass)




def token_login_check(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'access-token' in request.headers:
            token = request.headers['access-token']

        if not token:
            return jsonify({'message': 'token not available'}), 400

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'Message': 'Token Invalid'}),400

        if current_user.logged_in_state == 0:
            return jsonify({'Message': 'User Logged Out -> Login Required'}), 400
        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/')
def index():
    ''' Return the readme.md for the api '''
    #return '<h1> This page prints out API Documentation </h1>'
    with open(os.path.dirname(app.root_path) + '/RESTFul-API/readme.md', 'r') as markdown_file:
        # Read the content of the file
        content = markdown_file.read()
        # Convert to HTML
        return markdown.markdown(content)


@app.route('/api/register', methods=['POST'])
def create_user():
    username = request.json.get('username')
    password = request.json.get('password')
    confirm_password = request.json.get('confirm_password')
    firstName_lastName = request.json.get('full_name')
    fav_search_engine = request.json.get('search_engine_name')


    if username is None or password is None:
         return jsonify(
            {'Message': 'Both username and password fields are required'}), 400  # Need params username and password
    if confirm_password != password:
        return jsonify({'Message': 'Password and Confirm password fields need to match'}), 400  # Passwords do not match
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'Message': 'Username already taken'}), 400  # user exists
    if len(password) < 8:
        return jsonify({'Message': 'Minimum password length of 8 characters required'}), 400
    if len(password) > 64:
        return jsonify({'Message': 'Maximum password length is 64 characters'}), 400
    if password in open('/Users/nikhil/Desktop/RESTFul-API/top-10000.txt').read():
        return jsonify({'Message': 'Password is a common-password, Please use a new password'}), 400

    salt = token_bytes(16) # Generating secure random number for salt from secrets() for each user the salt is generated
    print(salt)
    user = User(username=username, firstName_lastName=firstName_lastName, fav_search_engine=fav_search_engine,logged_in_state=0,salt_pass=salt)

    user.hash_password(password,salt)  # Implement Hash Password from bcrypt
    db.session.add(user)
    db.session.commit()
    ret_data = {'user_id': username, 'full_name': firstName_lastName, 'Mother’s Favorite Search Engine': fav_search_engine}
    return jsonify(ret_data), 201

@app.route('/api/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'Message': 'Authenticatin Failed coz auth header problem '}), 400

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({'Message': 'Authenticatin Failed user doesnt exit'}), 400

    if user.verify_password(auth.password):
        user.logged_in_state = 1;
        db.session.commit()
        token = jwt.encode({'id': user.id , 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},app.config['SECRET_KEY'],algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})
    else:
        return jsonify({'Message': 'Authenticatin Failed'}), 400

@app.route('/api/user', methods= ['GET'])
@token_login_check
def get_user(current_user):
    user = current_user
    ret_data = {'user_name':user.username , 'full_name' : user.firstName_lastName ,'Mother’s Favorite Search Engine': user.fav_search_engine }
    return jsonify(ret_data),200

@app.route('/api/logout', methods=['POST'])
@token_login_check
def log_out(current_user):
    current_user.logged_in_state=0
    return jsonify({'Message': 'Logout Successful'}),200


if __name__ == '__main__':
    print("hello")
    if not os.path.exists('users.sqlite'):
        db.create_all()

    handler = RotatingFileHandler('/Users/nikhil/Desktop/RESTFul-API/log_file.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.run(host="localhost", port=5000, debug=True)
