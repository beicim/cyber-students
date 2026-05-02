from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

import api.handlers.helper as helper
from api.handlers.logout import LogoutHandler

from .base import BaseTest

class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
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

    async def login(self):
        # Store a hashed session token for authentication.
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
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}
        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    # Added headers to fetch request to ensure the token is included in the request.
    # Correct answer is 403 since the token is invalid, not 400 which indicates a missing token.
    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}
        response = self.fetch('/logout', method='POST', body=dumps(body), headers=headers)
        self.assertEqual(403, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}
        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)
        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(403, response_2.code)
