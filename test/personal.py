from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

import api.handlers.helper as helper
from api.personal import PersonalHandler

from .base import BaseTest

class PersonalHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/personal', PersonalHandler)])
        super().setUpClass()

    async def register(self):
        # Hash the seeded user passphrase for authentication tests.
        passphrase_hash, passphrase_salt = helper.hash_secret(self.password)
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.email, master_key)
        email_cipher, email_nonce = helper.encrypt_field(self.email, master_key)
        display_cipher, display_nonce = helper.encrypt_field(self.display_name, master_key)
        await self.get_app().db.users.insert_one({
            'email_id': email_id,
            'passphrase_hash': passphrase_hash,
            'passphrase_salt': passphrase_salt,
            'email': {
                'cipher': email_cipher,
                'nonce': email_nonce
            },
            'displayName': {
                'cipher': display_cipher,
                'nonce': display_nonce
            }
        })

    async def login(self):
        # Store a hashed token for the authenticated user.
        token_hash, token_salt = helper.hash_secret(self.token)
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.email, master_key)
        await self.get_app().db.users.update_one({
            'email_id': email_id
        }, {
            '$set': {
                'token_hash': token_hash,
                'token_salt': token_salt,
                'expiresIn': 2147483647
            }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_personal_post_and_get(self):
        headers = HTTPHeaders({'X-Token': self.token})

        personal_body = {
            'full_name': 'Jane Doe',
            'address': '123 Main St',
            'date_of_birth': '1990-01-01',
            'phone_number': '+1234567890',
            'disabilities': ['hearing', 'vision']
        }

        response = self.fetch('/personal', headers=headers, method='POST', body=dumps(personal_body))
        self.assertEqual(200, response.code)

        response = self.fetch('/personal', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(personal_body['full_name'], body_2['personal']['full_name'])
        self.assertEqual(personal_body['address'], body_2['personal']['address'])
        self.assertEqual(personal_body['date_of_birth'], body_2['personal']['date_of_birth'])
        self.assertEqual(personal_body['phone_number'], body_2['personal']['phone_number'])
        self.assertEqual(personal_body['disabilities'], body_2['personal']['disabilities'])

    def test_personal_missing_fields(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/personal', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual({}, body_2['personal'])

    def test_personal_data_encrypted_in_db(self):
        # Test that personal data is stored encrypted in the database.
        headers = HTTPHeaders({'X-Token': self.token})

        personal_body = {
            'full_name': 'Jane Doe',
            'address': '123 Main St',
            'date_of_birth': '1990-01-01',
            'phone_number': '+1234567890',
            'disabilities': ['hearing', 'vision']
        }

        # Post the personal data
        response = self.fetch('/personal', headers=headers, method='POST', body=dumps(personal_body))
        self.assertEqual(200, response.code)

        # Query the database directly to check encryption
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.email, master_key)
        user = IOLoop.current().run_sync(lambda: self.get_app().db.users.find_one({'email_id': email_id}, {'personal': 1}))

        self.assertIsNotNone(user)
        self.assertIn('personal', user)

        # Verify each field is encrypted and can be decrypted correctly
        for field_name, expected_value in personal_body.items():
            self.assertIn(field_name, user['personal'])
            field_data = user['personal'][field_name]
            self.assertIn('cipher', field_data)
            self.assertIn('nonce', field_data)

            # Decrypt and verify the value matches the original
            decrypted = helper.decrypt_field(field_data['cipher'], field_data['nonce'], master_key)
            self.assertIsNotNone(decrypted)

            if field_name == 'disabilities':
                # Disabilities is stored as JSON string
                self.assertEqual(expected_value, json_decode(decrypted))
            else:
                self.assertEqual(expected_value, decrypted)
