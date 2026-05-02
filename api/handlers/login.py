from datetime import datetime, timedelta, timezone
from tornado.escape import json_decode
# Import secrets to generate a secure session token.
import secrets
# Import helper for passphrase verification and token hashing.
import api.handlers.helper as helper
from .base import BaseHandler

class LoginHandler(BaseHandler):

    async def generate_token(self, email_id):
        token_value = secrets.token_urlsafe(32)
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()

        # Hash the raw session token before storing it in MongoDB.
        # Storing only the token hash and salt protects tokens in the database.
        token_hash, token_salt = helper.hash_secret(token_value)

        # Update the user record using the same deterministic email identifier.
        await self.db.users.update_one({
            'email_id': email_id
        }, {
            '$set': {
                'token_hash': token_hash,
                'token_salt': token_salt,
                'expiresIn': expires_in
            }
        })

        return {
            'token': token_value,
            'expiresIn': expires_in
        }

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
        except Exception:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        # Derive the AES master key from the system keyring.
        # This ensures the same key is used for both encryption and lookup of encrypted fields.
        master_key = helper.get_master_key()

        # Use a deterministic HMAC-based identifier for the email.
        # The actual email is stored encrypted in MongoDB, so we cannot query by plaintext email.
        email_id = helper.derive_email_id(email, master_key)

        # Lookup the user by the deterministic email identifier rather than plaintext email.
        user = await self.db.users.find_one({
          'email_id': email_id
        }, {
          'passphrase_hash': 1,
          'passphrase_salt': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Verify the provided passphrase against the stored PBKDF2 hash and salt.
        if not helper.verify_secret(password, user['passphrase_hash'], user['passphrase_salt']):
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = await self.generate_token(email_id)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
