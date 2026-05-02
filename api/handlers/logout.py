from tornado.web import authenticated

import api.handlers.helper as helper
from .auth import AuthHandler

class LogoutHandler(AuthHandler):

    @authenticated
    async def post(self):
        # Determine the user record to invalidate using the encrypted email identifier.
        # The user email itself is stored encrypted in the database, so this lookup uses email_id.
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.current_user['email'], master_key)

        # Invalidate the session by clearing the stored token hash, salt, and expiry.
        await self.db.users.update_one({
            'email_id': email_id,
        }, {
            '$set': {
                'token_hash': None,
                'token_salt': None,
                'expiresIn': None
            }
        })

        self.current_user = None

        self.set_status(200)
        self.write_json()
