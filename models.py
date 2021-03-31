# from api import db

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     public_id = db.Column(db.String(50), unique=True)
#     name = db.Column(db.String(50))
#     password = db.Column(db.String(80))

# class Message(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     senderId = db.Column(db.String(50))
#     reciverId = db.Column(db.String(50))
#     subject = db.Column(db.String(50))
#     message = db.Column(db.Text())
#     date = db.Column(db.String(50))
#     isOpend = db.Column(db.Boolean) 