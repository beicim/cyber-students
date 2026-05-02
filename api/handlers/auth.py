from datetime import datetime, timezone
# Import helper for token verification against stored PBKDF2 hashes.
import api.handlers.helper as helper
from .base import BaseHandler

class AuthHandler(BaseHandler):

    async def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except Exception:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        # Obtain the AES master key to decrypt stored email/displayName fields after token verification.
        master_key = helper.get_master_key()

        # Find users with an active token hash and salt so we can verify the supplied token.
        cursor = self.db.users.find({
            'token_hash': {'$ne': None},
            'token_salt': {'$ne': None}
        }, {
            'email.cipher': 1,
            'email.nonce': 1,
            'displayName.cipher': 1,
            'displayName.nonce': 1,
            'expiresIn': 1,
            'token_hash': 1,
            'token_salt': 1
        })

        user = None
        async for candidate in cursor:
            # Verify the bearer token against the stored PBKDF2 hash and salt.
            if not helper.verify_secret(token, candidate['token_hash'], candidate['token_salt']):
                continue

            # The token is valid; decrypt the email and displayName to populate current_user.
            email = helper.decrypt_field(candidate['email']['cipher'], candidate['email']['nonce'], master_key)
            display_name = helper.decrypt_field(candidate['displayName']['cipher'], candidate['displayName']['nonce'], master_key)
            if email is None or display_name is None:
                continue

            user = {
                'email': email,
                'displayName': display_name,
                'expiresIn': candidate['expiresIn']
            }
            break

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = datetime.now(timezone.utc).timestamp()
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        self.current_user = {
            'email': user['email'],
            'display_name': user['displayName']
        }
