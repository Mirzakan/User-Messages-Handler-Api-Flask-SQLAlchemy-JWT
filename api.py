from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from models import *
import jwt
import datetime
from functools import wraps
from sqlalchemy.orm.attributes import flag_modified

app = Flask(__name__)

file_path = os.path.abspath(os.getcwd())
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + file_path + '/user_msg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'Welcome {0} you have successfully registered!'.format(data['name'])})    

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('please enter your user name and password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/users')
def getAllUsers():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/users', methods=['DELETE'])
@token_required
def deleteAllUsers(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    users = User.query.all()
    if not users:
        return jsonify({'message' : 'No users found!'})
    db.session.query(User).delete()
    db.session.commit()
    return jsonify({'message' : 'users deleted!'}) 

@app.route('/writemsg', methods=['POST'])
@token_required
def writeMessage(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    request_data = request.get_json()
    users = User.query.all()
    for user in users:
        if(request_data['reciver'] == user.name):
            new_message = Message(senderId=current_user.name, reciverId=request_data['reciver'],
                subject=request_data['subject'], message=request_data['message'],
                    date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), isOpend=False)
            db.session.add(new_message)
            db.session.commit()
            return '<h4> Sender: {0} </br> Reciver: {1} </br> Subject: {2} </br> date: {3} </br>  Message: {4}</h4> <h5>Message Sent.<h5>'.format(
                new_message.senderId, new_message.reciverId, new_message.subject, new_message.date, new_message.message)
    return jsonify({'message':'user not found message was not delivered'})

@app.route('/messages/all')
def getAllMessages():
    messages = Message.query.all()
    output = []
    for msg in messages:
        msg_data = {}
        msg_data['sender'] = msg.senderId
        msg_data['reciver'] = msg.reciverId
        msg_data['subject'] = msg.subject
        msg_data['message'] = msg.message
        msg_data['date'] = msg.date
        msg_data['reading status'] = msg.isOpend
        output.append(msg_data)
    return jsonify({'messages' : output})

@app.route('/messages')
@token_required
def getAllUserMessages(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    messages = Message.query.all()
    output = []
    print(current_user)
    for msg in messages:
        if current_user.name == msg.reciverId:
            msg_data = {}
            msg_data['sender'] = msg.senderId
            msg_data['reciver'] = msg.reciverId
            msg_data['subject'] = msg.subject
            msg_data['message'] = msg.message
            msg_data['date'] = msg.date
            output.append(msg_data)
    return jsonify({'messages' : output}) if len(output) > 0 else '<h4>{0} there is no messages for you<h4>'.format(current_user.name)

@app.route('/messages/unread')
@token_required
def getUnreadedUserMessages(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    #search for users messages that havent been opened yet   
    messages = Message.query.filter_by(reciverId=current_user.name, isOpend=False).all()
    output = []
    for msg in messages:
        msg_data = {}
        msg.isOpend = True
        db.session.merge(msg)
        db.session.commit()
        msg_data['sender'] = msg.senderId
        msg_data['reciver'] = msg.reciverId
        msg_data['subject'] = msg.subject
        msg_data['message'] = msg.message
        msg_data['date'] = msg.date
        output.append(msg_data)
    return jsonify({'messages' : output}) if len(output) > 0 else '<h4>{0} there is no new messages for you<h4>'.format(current_user.name)

@app.route('/message')
@token_required
def readMessage(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    #get all messages as owner or as a reciver
    message = db.session.query(Message).filter(
        (Message.reciverId==current_user.name) | (Message.senderId==current_user.name) , Message.isOpend==False
    ).first()
    if not message:
        return jsonify({'message' : '{0} there is no new messages for you!'.format(current_user.name)}) 
    message.isOpend = True
    db.session.merge(message)
    db.session.commit()
    return jsonify({'message' : '{0} message (status: opened)'.format(message.message)}) 

@app.route('/message', methods=['DELETE'])
@token_required
def deleteMessage(current_user):
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    #get all messages as owner or as a reciver
    message = db.session.query(Message).filter(
        (Message.reciverId==current_user.name) | (Message.senderId==current_user.name)
    ).first()
    if not message:
        return jsonify({'message' : '{0} there is no new messages for you!'.format(current_user.name)}) 
    db.session.delete(message)
    db.session.commit()
    return jsonify({'message' : 'message deleted!'}) 

@app.route('/messages', methods=['DELETE'])
@token_required
def deleteAllMessages():
    if not current_user:
        return jsonify({'message' : 'you are not logged in (use provided token when signinup)'})
    messages = Message.query.all()
    if not messages:
        return jsonify({'message' : 'No messages found!'})
    db.session.query(Message).delete()
    db.session.commit()
    return jsonify({'message' : 'messages deleted!'}) 

if __name__ == '__main__':
    app.run(debug=True)