from client import *
from dateutil.parser import parse as date_parse
import getpass
logged_in_username = None

def register_cli():
    username = input('Enter username: ')
    password = getpass.getpass('Enter password (your password will not be visible due to security concerns): ')
    reenter_password = getpass.getpass('Re-enter password: ')
    if password != reenter_password:
        print('Passwords do not match, registration failed')
        return
    status_code, response = register(username, password)
    if status_code == 200:
        print('User registered successfully')
        user = response['user']
        print('Your user ID:', user['id'])
        print('Your username:', user['username'])
    elif status_code == 409:
        print('User already exists')
    else:
        print('Failed to register user with status code:', status_code)
    
def login_cli():
    global logged_in_username
    username = input('Enter username: ')
    password = getpass.getpass('Enter password (your password will not be visible due to security concerns): ')
    status_code, response = login(username, password)
    if status_code == 200:
        print('Logged in successfully')
        # Save the username for future requests as some client functions such as sharing note and get note 
        # require the username of the logged in user
        logged_in_username = username 
    elif status_code == 401:
        print('Invalid username or password')
    elif status_code == 404:
        print('User not found')
    else:
        print('Failed to login with status code:', response)

def find_user_cli():
    option = input('1. Find by username\n2. Find by ID\nEnter option:')
    if option.strip() == '1':
        username = input('Enter username: ')
        status_code, response = find_user(username=username)
        if status_code == 200:
            print('User found')
            for index, user in enumerate(response, start=1):
                print(f'{index}. Username: {user["username"]} (ID: {user["id"]})')
        else:
            print('Failed to find user with status code:', status_code)
    elif option.strip() == '2':
        user_id = input('Enter user ID: ')
        status_code, response = find_user(id=int(user_id))
        if status_code == 200:
            print('User found')
            for user in response:
                print(f'Username: {user["username"]} (ID: {user["id"]})')
        else:
            print('Failed to find user with status code:', status_code)

def share_note_cli():
    recipient_ids_string = input('Enter recipient IDs, seperated by commas: ')
    try:
        recipient_ids = [int(id) for id in recipient_ids_string.split(',')]
    except ValueError:
        print('Invalid recipient IDs')
        return
    
    file_path = input('Enter note\'s location (note is a file): ')
    expiration_hours = input('Enter expiration hours (default is 12 hours): ')

    try:
        expiration_seconds = int(float(expiration_hours) * 3600) if expiration_hours else 12 * 3600
    except ValueError:
        print('Invalid expiration hours')
        return
    
    max_access_count = input('Enter maximum access count for each user (default is 5): ')
    try:
        max_access_count = int(max_access_count) if max_access_count else 5
    except ValueError:
        print('Invalid maximum access count')
        return
    
    status_code, response = share_note_to_users(recipient_ids=recipient_ids, file_path=file_path, max_access_count=max_access_count,
                                                expiration_seconds=expiration_seconds, logged_username=logged_in_username)
    if status_code == 200:
        print('Note shared successfully')
        print('Note UUID: ', response['note_uuid'])
        print('Shared note URL: ', SERVER_ENDPOINT + response['url'])
    else:
        print('Failed to share note with status code:', status_code)

def get_user_notes_cli():
    status_code, response = get_user_notes()
    if status_code == 200:
        print('Your notes:')
        for index, note in enumerate(response, start=1):
            expiration = note['expiration']
            expiration = date_parse(expiration).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
            print('-' * 30)
            print(f'{index}. Name: {note['name']} - Note UUID: {note['note_uuid']} - Recipient user ID: {note['recipient_id']} - Access count: {note['access_count']}')
            print(f'Max access count: {note['max_access_count']} - Expiration: {expiration} - Sharing: {note['sharing']}')
            print('Note URL: ', SERVER_ENDPOINT + '/note/' + note['note_uuid'])
            print('-' * 30)
    else:
        print('Failed to get notes with status code:', status_code)

def get_shared_notes_cli():
    status_code, response = get_shared_notes()
    if status_code == 200:
        print('Shared notes:')
        for index, note in enumerate(response, start=1):
            expiration = note['expiration']
            expiration = date_parse(expiration).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
            print('-' * 30)
            print(f'{index}. Name: {note['name']} - Note UUID: {note['note_uuid']} - Access count: {note['access_count']}')
            print(f'Max access count: {note['max_access_count']} - Expiration: {expiration} - Sharing: {note['sharing']}')
            print('Note URL: ', SERVER_ENDPOINT + '/note/' + note['note_uuid'])
            print('-' * 30)
    elif status_code == 400 or status_code == 404:
        print(response.get('message'))
    else:
        print('Failed to get shared notes with status code: ', status_code)

def get_note_by_uuid_cli():
    def is_valid_url(url):
        return url.startswith('http://') or url.startswith('https://')
    note_uuid = input('Enter note UUID or URL: ')

    # Currently, custom URLs are not supported
    if is_valid_url(note_uuid):
        note_uuid = note_uuid.split('/')[-1]

    status_code, saved_note_path = get_note_by_uuid(note_uuid, logged_username=logged_in_username)
    if status_code == 200:
        print('Note saved at: ', os.path.join(download_note_path, saved_note_path))
    elif status_code == 400 or status_code == 404:
        print('Get noted failed with message: ', saved_note_path['message'])
    else:
        print(saved_note_path)
        print('Failed to get note with status code: ', status_code )

def delete_note_by_uuid_cli():
    note_uuid = input('Enter note UUID: ')
    status_code, response = delete_note_by_uuid(note_uuid)
    if status_code == 200:
        print('Note deleted successfully')
    else:
        print('Failed to delete note: ', response['message'] if type(response) == dict else response)

def toggle_share_note_by_uuid_cli():
    note_uuid = input('Enter note UUID: ')
    status_code, response = toggle_share_note_by_uuid(note_uuid)
    print(response['message'] if type(response) == dict else response)

def update_ephemeral_key_cli():
    username = input('Enter username: ')
    password = getpass.getpass('Enter password (your password will not be visible due to security concerns): ')
    status_code, response = update_key(username, password)
    print(response['message'] if type(response) == dict else response)

def cli_function():
    while True:
        print('-' * 30)
        print('1. Register a user')
        print('2. Login')
        print('3. Find a user')
        print('4. Share a note')
        print('5. Get your notes')
        print('6. Get shared notes')
        print('7. Get note by UUID/URL')
        print('8. Toggle sharing of a note by UUID')
        print('9. Delete a note by UUID')
        print('10. Update ephemeral public key on the server (requires login, will invalidate all shared notes)')
        print('11. Exit')
        print('-' * 30)
        option = input('Enter option: ')
        try:
            option = int(option.strip(' '))
        except ValueError:
            print('Invalid option')
            continue
        if option == 1:
            register_cli()
        elif option == 2:
            login_cli()
        elif option == 3:
            find_user_cli()
        elif option == 4:
            share_note_cli()
        elif option == 5:
            get_user_notes_cli()
        elif option == 6:
            get_shared_notes_cli()
        elif option == 7:
            get_note_by_uuid_cli()
        elif option == 8:
            toggle_share_note_by_uuid_cli()
        elif option == 9:
            delete_note_by_uuid_cli()
        elif option == 10:
            update_ephemeral_key_cli()
        elif option == 11:
            print('Exiting...')
            return 
        else:
            print('Invalid option')
            continue

if __name__ == '__main__':
    cli_function()

