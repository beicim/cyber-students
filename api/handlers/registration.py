from tornado.escape import json_decode

# Import helper for PBKDF2 hashing and key management.
import api.handlers.helper as helper
from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception('Display name must be a string')
        except Exception:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        # Obtain the AES master key from the system keyring.
        # This ensures the same key is used for encrypting email/displayName and for deriving lookup identifiers.
        master_key = helper.get_master_key()

        # Use a deterministic HMAC-derived identifier for the email.
        # The actual email will be stored encrypted in MongoDB, so we cannot query by plaintext.
        email_id = helper.derive_email_id(email, master_key)

        # Look up existing users by the derived email identifier.
        user = await self.db.users.find_one({
          'email_id': email_id
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Hash the user's passphrase before storing it in MongoDB.
        passphrase_hash, passphrase_salt = helper.hash_secret(password)

        # Encrypt email and display name using AES-GCM and store ciphertext + nonce.
        # This protects personal data at rest while still allowing decryption for authenticated access.
        email_cipher, email_nonce = helper.encrypt_field(email, master_key)
        display_cipher, display_nonce = helper.encrypt_field(display_name, master_key)

        await self.db.users.insert_one({
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

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
