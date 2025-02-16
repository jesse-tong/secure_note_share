import logging, sys
sys.path.insert(0, '../project_02_source')

from cli import *
import unittest
from faker import Faker
import time

class RegisterLoginTestCase(unittest.TestCase):
    def setUp(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        """Setup the test environment for login/register test case with a username (which will be used for testing later)"""
        cls.fake = Faker()
        cls.fake_username = cls.fake.user_name()

    def test_1_register(self):
        """Test if the user should be able to register successfully"""

        status_code, response = register(self.fake_username, 'test')
        self.assertEqual(status_code, 200)

    def test_2_register_already_exist_account(self):
        """Test if the user should't be able to register with the new account with the same username of an existing account"""

        status_code, response = register(self.fake_username, 'test')
        self.assertEqual(status_code, 409)

    def test_3_login_valid(self):
        """Test if the user should login successfully with valid username and password"""

        status_code, response = login(self.fake_username, 'test')
        self.assertEqual(status_code, 200)
    
    def test_4_login_invalid_password(self):
        """Test if the user should not be logged in with invalid password"""

        status_code, response = login(self.fake_username, 'invalid')
        self.assertEqual(status_code, 401)
    
    def test_5_login_invalid_username(self):
        """Test if the user should not be logged in with invalid username"""

        status_code, response = login('invalid_user', 'test')
        self.assertEqual(status_code, 401)

class AccessRestrictionTestCase(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Setup the test environment with Alice and Bob's account and a shared note from Alice to Bob"""
        cls.fake = Faker()
        cls.alice_username = cls.fake.user_name()
        cls.bob_username = cls.fake.user_name()
        cls.eve_username = cls.fake.user_name()
        cls.test_note_path = './test_data/test_note.txt'
        cls.expiration_time = 60

        status_code, response = register(cls.alice_username, 'test')
        cls.alice_id = response['user']['id']
        status_code, response = register(cls.bob_username, 'test')
        cls.bob_id = response['user']['id']
        status_code, response = register(cls.eve_username, 'test')
        cls.eve_id = response['user']['id']
        #Login to Alice's account
        status_code, response = login(cls.alice_username, 'test')
        #Send a note to Bob
        status_code, response, keys = share_note_to_users([cls.bob_id], cls.test_note_path, logged_username=cls.alice_username, expiration_seconds=cls.expiration_time, 
                                                          max_access_count=3, return_keys=True, return_shared_secrets=True)
        cls.note_share_start_time = time.time()

        cls.alice_derived_key = keys[cls.bob_id][0]
        cls.alice_shared_secret = keys[cls.bob_id][1]
        cls.note_uuid = response['note_uuid']
    
    def test_1_get_shared_notes(self):
        """Test if user can get shared notes correctly"""

        #Login to Bob's account
        status_code, response = login(self.bob_username, 'test')

        status_code, response = get_shared_notes()
        self.assertEqual(status_code, 200)
        self.assertTrue(len(response) > 0)
    
    def test_2_get_note_by_uuid_correct_encryption(self):
        """Test if the note fetched by get_note_by_uuid() is correctly encrypted and decrypted"""

        #Login to Bob's account
        status_code, response = login(self.bob_username, 'test')

        response = get_note_by_uuid(self.note_uuid, save_to_file=False, logged_username=self.bob_username)
        status_code = response[0]

        self.assertEqual(status_code, 200)
        self.assertTrue(response)
        with open(self.test_note_path, 'rb') as file:
            original_data = file.read()

        # Since save_to_file is False, the response will be a tuple with the note, derived key and the note metadata
        # if status_code == 200
        note = response[1]; bob_derived_key = response[2]
        # Check if the note from Bob is correct
        self.assertEqual(note, original_data)
        # Check if the key from Bob is correct to Alice's derived key
        self.assertEqual(bob_derived_key, self.alice_derived_key)

    def test_3_ensure_encryption_key_is_protected(self):
        """Test if the encryption key is protected from unauthorized access (with the note's encrypted data, metadata and salt)"""

        #Login to Bob's account
        status_code, response = login(self.bob_username, 'test')

        status_code, response = get_note_metadata(self.note_uuid)
        self.assertEqual(status_code, 200)
        note_metadata = response

        #Login as Eve and try to use data fetched from Alice's note to derive the shared symmetric key
        status_code, response = login(self.eve_username, 'test')
        eve_key, eve_shared_secret = key_from_note_and_username(note_metadata, self.eve_username, return_shared_secret=True)

        # Eve should not be able to derive the correct key that Alice and Bob share for this note
        # Eve's derived key should be different from Alice's derived key
        self.assertNotEqual(eve_key, self.alice_derived_key) 
        self.assertNotEqual(eve_shared_secret, self.alice_shared_secret)

    def test_4_ensure_exceed_access_count_is_not_accessible(self):
        """Test if the note should not be accessible after the access count exceeds the limit"""

        #Login to Bob's account
        status_code, response = login(self.bob_username, 'test')

        # As we set the max access count to 3, and we have already accessed it thrice
        # (two times in get_note_by_uuid() function and once in get_note_metadata() function)
        # the note should be expired now
        response = get_note_by_uuid(self.note_uuid, save_to_file=False, logged_username=self.bob_username)
        status_code = response[0]
        self.assertEqual(status_code, 400)

    def test_5_ensure_expired_notes_are_not_accessible(self):
        """Test if the note should not be accessible after the expiration time"""

        status_code, response = login(self.alice_username, 'test')
        expiration_time = 1
        #Send a note to Bob
        status_code, response, keys = share_note_to_users([self.bob_id], self.test_note_path, logged_username=self.alice_username, expiration_seconds=expiration_time, 
                                                          max_access_count=3, return_keys=True)
        
        self.assertEqual(status_code, 200)
        new_note_uuid = response['note_uuid'] # Get the new UUID for the new note

        time.sleep(expiration_time + 1) # Wait for the note to expire
        status_code, response = login(self.bob_username, 'test')
        response = get_note_by_uuid(new_note_uuid, save_to_file=False, logged_username=self.bob_username)
        status_code = response[0]
        self.assertEqual(status_code, 400)

class SessionKeyTestCase(unittest.TestCase):
    def setUp(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        cls.fake = Faker()
        cls.alice_username = cls.fake.user_name()
        cls.bob_username = cls.fake.user_name()
        cls.test_note_path = './test_data/test_note.txt'
        cls.expiration_time = 30

        status_code, response = register(cls.alice_username, 'test')
        cls.alice_id = response['user']['id']
        status_code, response = register(cls.bob_username, 'test')
        cls.bob_id = response['user']['id']
    
    def test_1_ensure_session_key_for_each_note_are_different(self):
        """Test if the session key for each note to different user is different (each note should have a different session key)"""
        
        status_code, response = login(self.alice_username, 'test')
        #Send a note to Bob
        status_code, response, first_note_keys = share_note_to_users([self.bob_id], self.test_note_path, logged_username=self.alice_username, expiration_seconds=5, 
                                                          max_access_count=3, return_keys=True)
        
        status_code, response, second_note_keys = share_note_to_users([self.bob_id], self.test_note_path, logged_username=self.alice_username, expiration_seconds=5,
                                                            max_access_count=3, return_keys=True)
        
        for key in first_note_keys.values():
            self.assertNotIn(key, second_note_keys.values())

    def test_2_ensure_both_parties_have_same_session_key(self):
        """Test if both parties (sender and receiver) have the same session key for the same note"""
        
        status_code, response = login(self.alice_username, 'test')
        #Send a note to Bob
        status_code, response, keys = share_note_to_users([self.bob_id], self.test_note_path, logged_username=self.alice_username, expiration_seconds=60, 
                                                          max_access_count=3, return_keys=True)
        
        status_code, response = login(self.bob_username, 'test')
        status_code, notes = get_shared_notes()
        note_uuid = notes[0]['note_uuid']
        status_code, response = get_note_metadata(note_uuid)
        note_metadata = response
        bob_key = key_from_note_and_username(note_metadata, self.bob_username)
        alice_key = keys[self.bob_id]

        self.assertEqual(bob_key, alice_key)
    

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    runner = unittest.TextTestRunner(verbosity=2)
    unittest.main(testRunner=runner)

        