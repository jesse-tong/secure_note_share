from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_login import login_manager, LoginManager, login_required, current_user
import uuid, json, jwt, os, hashlib, base64, dataclasses, atexit
from server_schema import db, User, Note
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from apscheduler.schedulers.background import BackgroundScheduler

def dataclass_obj_to_dict(obj):
    return dataclasses.asdict(obj)

app = Flask(__name__)
CORS(app, expose_headers='Authorization')
app.config.from_file('env.json', load=json.load)
db.init_app(app)
login_manager = LoginManager()

# Delete expired notes every 2 hour, first run time is 5 minutes after the app starts
def delete_expired_notes():
    with app.app_context():
        current_date = datetime.now(timezone.utc)
        current_date = current_date.replace(tzinfo=None)
        delete_count = db.session.query(Note).filter(Note.expiration < current_date).delete()
        db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_expired_notes, trigger='interval', hours=2, next_run_time=datetime.now() + timedelta(minutes=5))
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Load the user from the login JWT token
#Reference: https://medium.com/@gelsonm/authenticating-a-flask-api-using-json-web-tokens-c4d97e490776
# https://stackoverflow.com/questions/50856038/using-flask-login-and-flask-jwt-together-in-a-rest-api
@login_manager.request_loader
def load_user_from_request(request):
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return None
    token = authorization_header.replace('Bearer ', '', 1)

    if not token:
        return None
    try:
        data = jwt.decode(token, app.config['SECRET_JWT_KEY'], algorithms=['HS256'])
        user = db.session.query(User).filter_by(id=data['id']).first()
    
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        print(e)
        return None


@app.route('/register', methods=['POST'])
def register():
    request_data = request.get_json()
    username = request_data.get('username')
    password = request_data.get('password')
    public_key_pem = request_data.get('public_key_pem')

    if not username or not password or not public_key_pem:
        return jsonify({'message': 'Missing required fields'}), 400
    
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100)
    salt = base64.b64encode(salt).decode('utf-8')
    hashed_password = base64.b64encode(hashed_password).decode('utf-8')

    try:
        new_user = User(username=username, password=hashed_password, salt=salt, public_key_pem=public_key_pem)
        db.session.add(new_user)
        db.session.commit()
    except:
        return jsonify({'message': 'User already exists!'}), 409
    return jsonify({'message': 'New user created!', 'user': dataclass_obj_to_dict(new_user)}), 200

def is_valid_pem(public_key_pem):
        return public_key_pem.startswith('-----BEGIN PUBLIC KEY-----') and public_key_pem.endswith('-----END PUBLIC KEY-----\n')

@app.route('/update_public_key', methods=['POST'])
def update_public_key():
    
    request_data = request.get_json()
    username = request_data.get('username')
    password = request_data.get('password')
    user = db.session.query(User).filter_by(username=username).first()

    if not user:
        return jsonify({'message': 'User not found!'}), 404
    salt = base64.b64decode(user.salt)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100)
    saved_hashed_password = base64.b64decode(user.password)

    if saved_hashed_password == hashed_password:
        new_public_key_pem = request_data.get('public_key_pem')
        if not new_public_key_pem:
            return jsonify({'message': 'Missing public key'}), 400
        if not is_valid_pem(new_public_key_pem):
            return jsonify({'message': 'Invalid public key format!'}), 400
        
        user.public_key_pem = new_public_key_pem
        db.session.commit()
        return jsonify({'message': 'Public key updated!'}), 200
    else:
        return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()
    username = request_data.get('username')
    password = request_data.get('password')
    user = db.session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 401
    salt = base64.b64decode(user.salt)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100)
    saved_hashed_password = base64.b64decode(user.password)
    
    if hashed_password == saved_hashed_password:
        token = jwt.encode({'id': user.id, 'exp': datetime.now(timezone.utc) + timedelta(minutes=30)}, app.config['SECRET_JWT_KEY'], algorithm='HS256')
        return jsonify({'message': 'Login success!', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user_id = int(user_id)
    user = db.session.query(User).filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    return jsonify(dataclass_obj_to_dict(user))

@app.route('/user/public_key', methods=['GET'])
def get_public_key_of_users():
    user_ids = request.args.to_dict(flat=False).get('user_ids[]')
    if not user_ids:
        return jsonify({'message': 'Missing required fields'}), 400
    user_ids = [int(user_id) for user_id in user_ids]
    users = db.session.query(User).filter(User.id.in_(user_ids)).all()
    if not users:
        return jsonify({'message': 'User not found!'}), 404
    return jsonify([dataclass_obj_to_dict(user) for user in users])


@app.route('/notes', methods=['GET'])
@login_required
def get_notes():
    current_user_id = current_user.id
    user = db.session.query(User).filter_by(id=current_user_id).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    current_date = datetime.now(timezone.utc)
    current_date = current_date.replace(tzinfo=None)
    notes = db.session.query(Note).filter_by(sender_id=current_user_id).all()
    
    notes = [note for note in notes if note.expiration > current_date]
    
    notes = [dataclass_obj_to_dict(note) for note in notes]
    
    # Remove the content from the response since this route return a list of all notes
    for note in notes:
        note.pop('content')

    return jsonify(notes)

@app.route('/notes/shared_with_me', methods=['GET'])
@login_required
def get_shared_notes():
    current_user_id = current_user.id
    user = db.session.query(User).filter_by(id=current_user_id).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    current_date = datetime.now(timezone.utc)
    current_date = current_date.replace(tzinfo=None)
    notes = db.session.query(Note).filter_by(recipient_id=current_user_id).all()
    
    notes = [note for note in notes if note.expiration > current_date 
             and note.sharing and (note.max_access_count - 1) >= note.access_count]
    
    notes = [dataclass_obj_to_dict(note) for note in notes]
    for note in notes:
        note.pop('content')
    
    return jsonify(notes)

@app.route('/user/search', methods=['GET'])
def search_user():
    username = request.args.get('username')
    id = request.args.get('id')
    query = db.session.query(User)
    if username:
        query = query.filter(User.username.ilike(f'%{username}%'))
    if id:
        query = query.filter_by(id=id)
    users = query.all()

    if not users:
        return jsonify({'message': 'User not found!'}), 404
    return jsonify([dataclass_obj_to_dict(user) for user in users])

@app.route('/note', methods=['POST'])
@login_required
def add_note():
    request_data = request.get_json()
    recipient_id_content = request_data.get('notes[]')
    name = request_data.get('name')
    expiration = request_data.get('expiration')
    max_access_count = request_data.get('max_access_count') if request_data.get('max_access_count') else 1

    try:
        expiration = parse(expiration)
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
    except:
        return jsonify({'message': 'Invalid expiration date format!'}), 400

    if not recipient_id_content or not name or not expiration:
        return jsonify({'message': 'Missing required fields'}), 400
    
    note_uuid = uuid.uuid4().hex
    for recipient in recipient_id_content:
        recipient_id = recipient['id']
        content = recipient['content']
        salt = recipient['salt']
        # Decode the content from base64
        content = base64.b64decode(content.encode('utf-8'))
        new_note = Note(sender_id=current_user.id, recipient_id=recipient_id, name=name, content=content, 
                        expiration=expiration, note_uuid=note_uuid, salt=salt, max_access_count=max_access_count)
        db.session.add(new_note)
    db.session.commit()

    return jsonify({'message': 'Note added!', 'note_uuid': note_uuid, 'url': f'/note/{note_uuid}'}), 200

@app.route('/note/<uuid>', methods=['GET', 'DELETE'])
@login_required
def get_delete_note(uuid):
    if request.method == 'GET':
        current_user_id = current_user.id
        user = db.session.query(User).filter_by(id=current_user_id).first()
        note = db.session.query(Note).filter_by(note_uuid=uuid, recipient_id=current_user_id).first()
        
        if not note:
            return jsonify({'message': 'Note not found or you are not one of the repicient for this note!'}), 400
        
        sender = db.session.query(User.public_key_pem).filter_by(id=note.sender_id).first()

        if not user or not sender:
            return jsonify({'message': 'User not found!'}), 404
        
        # In case of max access count exceeded or note expired, automatically delete the note and not return it
        now_utc = datetime.now(timezone.utc)
        # Remove tzinfo from now_utc since SQLite does not support timezone aware datetime
        now_utc = now_utc.replace(tzinfo=None)
        if note.access_count >= (note.max_access_count - 1) or note.expiration < now_utc:
            db.session.delete(note)
            db.session.commit()
            return jsonify({'message': 'Note expired or access count exceeded!'}), 400
        
        note.access_count += 1
        db.session.commit()
        note_obj = dataclass_obj_to_dict(note)

        # Encode the binary content to base64
        note_obj['content'] = base64.b64encode(note_obj['content']).decode('utf-8')
        note_obj['sender_public_key_pem'] = sender.public_key_pem

        return jsonify(note_obj)
    elif request.method == 'DELETE':
        deleted_note_count = db.session.query(Note).filter_by(note_uuid=uuid, sender_id=current_user.id).delete()
        if deleted_note_count == 0:
            return jsonify({'message': 'Note not found or you are not the sender of this note!'}), 400
        db.session.commit()
        return jsonify({'message': f'Note with ID {uuid} deleted!'}), 200

@app.route('/note/<uuid>/toggle_share', methods=['GET', 'POST'])
@login_required
def toggle_sharing(uuid):
    notes = db.session.query(Note).filter_by(note_uuid=uuid, sender_id=current_user.id).all()
    if not notes:
        return jsonify({'message': 'Note not found or you are not the sender of this note!'}), 400
    db.session.query(Note).filter_by(note_uuid=uuid).update({'sharing': not notes[0].sharing})
    db.session.commit()
    return jsonify({'message': 'Sharing status updated!'}), 200
    
if __name__ == '__main__':
    login_manager.init_app(app) 
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
