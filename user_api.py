
import os
import markdown as markdown
from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import datetime
import bcrypt
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
    hash_pass = db.Column(db.String(75))
    firstName_lastName = db.Column(db.String(100))
    fav_search_engine = db.Column(db.String(50))
    logged_in_state = db.Column(db.Integer)

    # needs to be re-implementeed
    def hash_password(self, password):
        salt = bcrypt.gensalt(rounds=12)
        self.hash_pass = bcrypt.hashpw(password.encode(), salt)

    def verify_password(self, password):
        if bcrypt.checkpw(password.encode(), self.hash_pass):
            return True
        else:
            app.logger.error('%s  : Failed login attempt of user with user_id: %d ', str(datetime.datetime.now()) ,self.id)
            return False

        # return bcrypt.checkpw(password.encode(), self.hash_pass)



'''
Token validation is done
Security Checks: Expiration time is set, Whitelisting is done on the algorithm header part to prevent any tampering of the token during transit
'''
def token_login_check(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'access-token' in request.headers:
            token = request.headers['access-token']

        if not token:
            return jsonify({'message': 'token not recieved'}), 400

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            header_jwt = jwt.get_unverified_header(token)
            if(header_jwt['alg'] != 'HS512'): # Added whitelist to prevent downgrading of digital signature
                print(header_jwt['alg'] )
                return jsonify({'Message': 'Token Invalid'}), 400
            user_id = data['id']
            current_user = User.query.filter_by(id=user_id).first()
        except:
            return jsonify({'Message': 'Token Invalid'}),400

        if current_user.logged_in_state == 0:
            return jsonify({'Message': 'User Logged Out -> Login Required'}), 400
        return f(current_user, *args, **kwargs)
    return decorator

'''
API Documentation sent to the user as HTML Markdown
'''
@app.route('/')
def index():
    ''' Return the readme.md for the api '''
    with open(os.path.dirname(app.root_path) + 'README.md', 'r') as markdown_file:
        # Read the content of the file
        content = markdown_file.read()
        # Convert to HTML
        return markdown.markdown(content)

'''
Route for registering a user: Get account creation details from JSON body
Secure Practices: Password Storage - OWASP and NIST recommendations for password storage are followed
'''
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
    if len(username) > 32:
        return jsonify({'Message': 'Maximum username length is 32 characters'}), 400
    if len(password) > 64:
        return jsonify({'Message': 'Maximum password length is 64 characters'}), 400
    if password in open('top-10000.txt').read():
        return jsonify({'Message': 'Password is a common-password, Please use a new password'}), 400


    user = User(username=username, firstName_lastName=firstName_lastName, fav_search_engine=fav_search_engine,logged_in_state=0)

    user.hash_password(password)  # Implement Hash Password from bcrypt
    db.session.add(user)
    db.session.commit()
    ret_data = {'user_id': username, 'full_name': firstName_lastName, 'Mothers Favorite Search Engine': fav_search_engine}
    return jsonify(ret_data), 201

'''
Route for logging in - get authentication details from request.authorization headers
Security Features: Generic Error messages
'''
@app.route('/api/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'Message': 'Authentication Failed'}), 400

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({'Message': 'Authentication Failed'}), 400

    if user.verify_password(auth.password):
        user.logged_in_state = 1;
        db.session.commit()
        token = jwt.encode({'id': user.id , 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},app.config['SECRET_KEY'],algorithm='HS512')
        return jsonify({'token': token.decode('UTF-8')})
    else:
        return jsonify({'Message': 'Authenticatin Failed'}), 400

'''
Route for getting user details - Get token details from 'access-token' header
Security Features: Validate the JWT token and Logged in state to give access to the route
'''
@app.route('/api/user', methods= ['GET'])
@token_login_check
def get_user(current_user):
    user = current_user
    ret_data = {'user_name':user.username , 'full_name' : user.firstName_lastName ,'Mothers Favorite Search Engine': user.fav_search_engine }
    return jsonify(ret_data),200

'''
Route for logout - Get token details from 'access-token' header
Security Features: Validate the JWT token and Logged in state to give access to the route
'''
@app.route('/api/logout', methods=['POST'])
@token_login_check
def log_out(current_user):
    current_user.logged_in_state=0
    db.session.commit()
    return jsonify({'Message': 'Logout Successful'}),200


if __name__ == '__main__':
    if not os.path.exists('users.sqlite'):
        db.create_all()
    handler = RotatingFileHandler('log_file.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.run(host="localhost", port=5000, debug=True)
