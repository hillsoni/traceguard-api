import hashlib
import re
from flask import jsonify
from flask_jwt_extended import create_access_token,create_refresh_token
from app.models.user import User
from app.models.revoked_token import RevokedTokenModel
from app.extensions import db, jwt

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']  
    return RevokedTokenModel.is_jti_blacklisted(jti)

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error': 'Token has been revoked',
        'message': 'Please log in again'
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error': 'Token has expired',
        'message': 'Please refresh your token or log in again'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'error': 'Invalid token',
        'message': 'Token verification failed'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'error': 'Authorization required',
        'message': 'No token provided'
    }), 401

def encrypt_password(password):
    password=hashlib.md5(password.encode()).hexdigest()
    return password

def insert_data(data):
    print(data)
    encrypted_pass=encrypt_password(data["password"])
    user= User(
        email = data["email"],
        username = data["username"],
        password = encrypted_pass,
    )
    db.session.add(user)
    db.session.commit()

class UserValidation:

    @staticmethod
    def register_validation(data):

        if not all([
            data["email"],data["username"],
            data["password"], data["confirm"], 
        ]):
            return None, "All fields required", 400

        if User.query.filter_by(email=data["email"]).first():
            return None, "Email already exists", 400

        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, data["email"]):
            return None, "Invalid Email", 400

        if len(data["password"]) < 6 or len(data["password"]) > 12:
            return None, "Password must be 6-12 chars", 400

        if data["password"] != data["confirm"]:
            return None, "Passwords mismatch", 400

        insert_data(data)

        access_token = create_access_token(identity=data["email"])
        refresh_token = create_refresh_token(identity=data["email"])
        
        return {
            'message': f'User {data["email"]} was created',
            'access_token': access_token,
            'refresh_token': refresh_token
        }, None, 201


    @staticmethod
    def login_validation(data):
        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            return None, "User not found", 404
        if user.password != encrypt_password(data["password"]):
            return None, "Wrong password", 400
        token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        return {"access_token": token,
                'refresh_token': refresh_token
                }, None, 200
    
    @staticmethod
    def refresh(user):
        user = User.query.filter_by(email=user).first()

        new_access_token = create_access_token(
            identity=user.email
        )

        return {'access_token': new_access_token},None, 200


    @staticmethod
    def logout_validation(jti):
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return {'message': 'Successfully logged out'},None, 200
