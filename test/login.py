from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

import api.handlers.helper as helper
from .base import BaseTest

from api.handlers.login import LoginHandler

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    async def register(self):
        # Hash the passphrase for the seeded user account.
        passphrase_hash, passphrase_salt = helper.hash_secret(self.password)
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.email, master_key)
        email_cipher, email_nonce = helper.encrypt_field(self.email, master_key)
        display_cipher, display_nonce = helper.encrypt_field('testDisplayName', master_key)
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

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
