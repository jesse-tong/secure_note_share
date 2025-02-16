import requests
import json
from key_share import *
from typing import Any
from aes import *
from requests.models import PreparedRequest
from datetime import datetime, timedelta, timezone  
from dateutil.parser import parse
import hashlib, json

with open('env.json') as file:
    env = json.load(file)

download_note_path = env.get('DOWNLOAD_NOTE_PATH')

try:
    os.makedirs(download_note_path)
except FileExistsError:
    pass

SERVER_ENDPOINT = 'http://localhost:5000'

REGISTER_URL = f'{SERVER_ENDPOINT}/register'
LOGIN_URL = f'{SERVER_ENDPOINT}/login'
UPDATE_KEY_URL = f'{SERVER_ENDPOINT}/update_public_key'
SHARED_NOTES_WITH_ME_URL = f'{SERVER_ENDPOINT}/notes/shared_with_me'
SEARCH_USER_URL = f'{SERVER_ENDPOINT}/user/search'
GET_USER_NOTES_URL = f'{SERVER_ENDPOINT}/notes'
GET_USER_EPHEREMAL_PUBLIC_KEY_URL = f'{SERVER_ENDPOINT}/user/public_key'
SHARE_NOTE_URL = f'{SERVER_ENDPOINT}/note'

session = requests.Session()

def register(username, password):
    private_key = init_or_load_ephemeral_key(username=username)
    public_key_pem = serialize_public_key(private_key.public_key())
    json = {'username': username, 'password': password, 'public_key_pem': public_key_pem.decode()}

    response = session.post(REGISTER_URL, json=json)

    if response.status_code == 200:
        return 200, response.json()
    elif response.status_code == 409:
        return 409, response.json()
    else:
        return response.status_code, response.text
    
def login(username: str, password: str):
    global session
    response = session.post(LOGIN_URL, json={'username': username, 'password': password})
    if response.status_code == 200:
        token = response.json().get('token')
        session.headers.update({'Authorization': f'Bearer {token}'})
        return 200, response.json()
    elif response.status_code == 401:
        # Invalid credentials
        return 401, response.json()
    elif response.status_code == 404:
        # User not found
        return 404, response.json()
    else:
        return response.status_code, response.text

    
def update_key(username: str, password: str):
    private_key = init_or_load_ephemeral_key(username)

    public_key_pem = serialize_public_key(private_key.public_key())
    json = {'username': username, 'password': password, 'public_key_pem': public_key_pem.decode()}
    response = session.post(UPDATE_KEY_URL, json=json)
    if response.status_code == 200:
        return response.status_code, response.json()
    if response.status_code == 401:
        # Invalid credentials
        return response.status_code, response.json()
    if response.status_code == 400: 
        # Invalid public key format
        return response.status_code, response.json()
    else:
        print('Failed to update public key')
        return response.status_code, response.text

def find_user(username: str = None, id: int = None):
    req = PreparedRequest()
    params = {}
    if username:
        params['username'] = username
    if id:
        params['id'] = id
    req.prepare_url(SEARCH_USER_URL, params)
    response = session.get(req.url)
    if response.status_code == 200:
        return response.status_code, response.json()
    else:
        return response.status_code, response.text
    
def get_user_notes():
    response = session.get(GET_USER_NOTES_URL)
    if response.status_code == 200:
        return response.status_code, response.json()
    else:
        return response.status_code, response.text
    
def get_shared_notes():
    response = session.get(SHARED_NOTES_WITH_ME_URL)
    if response.status_code == 200:
        return response.status_code, response.json()
    else:
        return response.status_code, response.text

# return_keys is used for testing purposes to return the keys for each recipient
# return_shared_secrets is used for testing purposes to return the shared secrets for each recipient along with the keys
# but it is only used when return_keys is True
def share_note_to_users(recipient_ids: list, file_path: str, expiration_seconds: int = 7200, 
                        max_access_count: int = 5, logged_username: str = None, return_keys=False, return_shared_secrets=False):
    req = PreparedRequest()
    req.prepare_url(GET_USER_EPHEREMAL_PUBLIC_KEY_URL, {'user_ids[]': recipient_ids})

    recipient_keys_response = session.get(req.url)
    if recipient_keys_response.status_code != 200:
        print('Error getting recipients\' public keys')
        return recipient_keys_response.status_code, recipient_keys_response.text
    
    recipient_keys = recipient_keys_response.json()
    recipient_keys = [( key['id'], deserialize_public_key(key['public_key_pem'].encode()) ) for key in recipient_keys]

    filename = os.path.basename(file_path)
    expiration = datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds)
    # Round the expiration time to the nearest second, since the database will return the expiration time rounded to the nearest second
    # Thus making the fetched expiration time of the recipient mismatch to the sender -> Incorrect key derivation tag
    # -> Incorrect key
    expiration = expiration.replace(microsecond=0)

    note_content_for_each_recipient = []
    encrypt_keys = {}
    for id, recipient_key in recipient_keys:
        # Create metadata used for key derivation
        shared_secret = compute_shared_secret(init_or_load_ephemeral_key(username=logged_username), recipient_key)
        salt = os.urandom(16)
        name_and_expire_iso_date_hash = hashlib.sha256(f'{filename}{expiration.isoformat()}'.encode()).digest()
        # Derive a key for each recipient
        key = derive_key(shared_secret, salt=salt, info=name_and_expire_iso_date_hash)

        #If return_keys is True, return the keys for each recipient (this is for testing purposes)
        if return_keys:
            if return_shared_secrets:
                encrypt_keys[id] = (key, shared_secret)
            else:
                encrypt_keys[id] = key

        encrypted_base64 = file_to_encrypted_base64(file_path, key)
        note_content_for_each_recipient.append({'id': id, 'content': encrypted_base64, 'salt': base64.b64encode(salt).decode()})

    json = {'name': filename, 'expiration': expiration.isoformat(), 'max_access_count': max_access_count,
             'notes[]': note_content_for_each_recipient}

    response = session.post(SHARE_NOTE_URL, json=json)

    if return_keys and response.status_code == 200:
        return response.status_code, response.json(), encrypt_keys
    elif return_keys and response.status_code != 200:
        return response.status_code, response.text, encrypt_keys
    elif not return_keys and response.status_code == 200:
        return 200, response.json()
    else:
        return response.status_code, response.text

# These functions are used for testing purposes
def get_note_metadata(note_uuid: str):
    response = session.get(f'{SERVER_ENDPOINT}/note/{note_uuid}')
    if response.status_code == 200:
        note = response.json()

        return 200, note
    elif response.status_code == 400 or response.status_code == 404:
        return response.status_code, response.json()
    else:
        return response.status_code, response.text
    
def key_from_note_and_username(note: Any, username: str = None, return_shared_secret=False):
    note_base64_encrypted = note['content']
    sender_public_key_pem = note['sender_public_key_pem']
    salt = base64.b64decode(note['salt'].encode())
    filename = note['name']
    expiration = note['expiration']
    expiration = parse(expiration).isoformat() # Convert to ISO 8601 format

    user_private_key = init_or_load_ephemeral_key(username=username)
    sender_public_key = deserialize_public_key(sender_public_key_pem.encode())
    shared_secret = compute_shared_secret(user_private_key, sender_public_key)
    name_and_expire_iso_date_hash = hashlib.sha256(f'{filename}{expiration}'.encode()).digest()
    decrypt_key = derive_key(shared_secret, salt=salt, info=name_and_expire_iso_date_hash)
    
    if return_shared_secret:
        return decrypt_key, shared_secret
    else:
        return decrypt_key
# End of testing functions

def get_note_by_uuid(note_uuid: str, save_to_file: bool = True, logged_username: str = None):
    user_private_key = init_or_load_ephemeral_key(username=logged_username)
    response = session.get(f'{SERVER_ENDPOINT}/note/{note_uuid}')

    if response.status_code == 200:
        note = response.json()
        sender_public_key_pem = note['sender_public_key_pem']
        note_base64_encrypted = note['content']
        salt = base64.b64decode(note['salt'].encode())

        filename = note['name']
        expiration = note['expiration']
        expiration = parse(expiration).isoformat() # Convert to ISO 8601 format
        name_and_expire_iso_date_hash = hashlib.sha256(f'{filename}{expiration}'.encode()).digest()

        sender_public_key = deserialize_public_key(sender_public_key_pem.encode())
        shared_secret = compute_shared_secret(user_private_key, sender_public_key)
        decrypt_key = derive_key(shared_secret, salt=salt, info=name_and_expire_iso_date_hash)

        note_name = note['name']
        note_data = encrypted_base64_to_bytes(note_base64_encrypted, decrypt_key)
        if save_to_file:
            with open(os.path.join(download_note_path, note_name), 'wb') as file:
                file.write(note_data)

            return 200, note_name
        else:
            return 200, note_data, decrypt_key
    elif response.status_code == 400 or response.status_code == 404:
        return response.status_code, response.json()
    else:
        return response.status_code, response.text


def delete_note_by_uuid(note_uuid: str):
    response = session.delete(f'{SERVER_ENDPOINT}/note/{note_uuid}')
    if response.status_code == 200:
        return 200, response.json()
    elif response.status_code == 400:
        return 400, response.json() # Note not found or the user is not the sender
    else:
        return response.status_code, response.text
    
def toggle_share_note_by_uuid(note_uuid: str):
    response = session.post(f'{SERVER_ENDPOINT}/note/{note_uuid}/toggle_share')
    if response.status_code == 200:
        return 200, response.json()
    elif response.status_code == 400:
        return 400, response.json() # Note not found or the user is not the sender
    else:
        return response.status_code, response.text
    