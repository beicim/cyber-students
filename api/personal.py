import json

from tornado.web import authenticated

import api.handlers.helper as helper
from .handlers.auth import AuthHandler

class PersonalHandler(AuthHandler):

    @authenticated
    async def get(self):
        # Retrieve only the personal section for the authenticated user.
        # We authenticate the request first, then use a deterministic email_id lookup.
        master_key = helper.get_master_key()
        email_id = helper.derive_email_id(self.current_user['email'], master_key)

        user = await self.db.users.find_one({
            'email_id': email_id
        }, {
            'personal': 1
        })

        # Build a response object with decrypted personal fields.
        personal = {}
        master_key = helper.get_master_key()

        if user is None or 'personal' not in user:
            # If the user has no personal data yet, return an empty object.
            self.set_status(200)
            self.response['personal'] = personal
            self.write_json()
            return

        # Decrypt each personal field if it exists in the stored document.
        for field_name in ['full_name', 'address', 'date_of_birth', 'phone_number', 'disabilities']:
            field_data = user['personal'].get(field_name) if user.get('personal') else None
            if field_data is None:
                continue
            cipher = field_data.get('cipher')
            nonce = field_data.get('nonce')
            if cipher is None or nonce is None:
                continue
            plaintext = helper.decrypt_field(cipher, nonce, master_key)
            if plaintext is None:
                continue
            if field_name == 'disabilities':
                try:
                    personal[field_name] = json.loads(plaintext)
                except Exception:
                    personal[field_name] = None
            else:
                personal[field_name] = plaintext

        self.set_status(200)
        self.response['personal'] = personal
        self.write_json()

    @authenticated
    async def post(self):
        await self._save_personal()

    @authenticated
    async def put(self):
        await self._save_personal()

    async def _save_personal(self):
        # Read the incoming JSON body from the request arguments.
        body = self.request.arguments
        master_key = helper.get_master_key()
        update_fields = {}

        for field_name in ['full_name', 'address', 'date_of_birth', 'phone_number', 'disabilities']:
            if field_name not in body:
                continue

            field_value = body[field_name]
            if field_value is None:
                continue

            if isinstance(field_value, (list, dict)):
                field_value = json.dumps(field_value)
            elif not isinstance(field_value, str):
                field_value = str(field_value)

            ciphertext, nonce = helper.encrypt_field(field_value, master_key)
            if ciphertext is None or nonce is None:
                continue

            update_fields[f'personal.{field_name}.cipher'] = ciphertext
            update_fields[f'personal.{field_name}.nonce'] = nonce

        if update_fields:
            # Use the same deterministic email_id for personal-data updates.
            master_key = helper.get_master_key()
            email_id = helper.derive_email_id(self.current_user['email'], master_key)
            await self.db.users.update_one({
                'email_id': email_id
            }, {
                '$set': update_fields
            })

        self.set_status(200)
        self.response['personal'] = body
        self.write_json()
