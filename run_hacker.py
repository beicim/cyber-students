import asyncio
import click
from motor.motor_tornado import MotorClient

from api.conf import MONGODB_HOST, MONGODB_DBNAME

async def get_users(db):
    # Fetch all fields – these are now hashes, salts, encrypted blobs
    cur = db.users.find({}, {
        'email_id': 1,
        'email': 1,
        'displayName': 1,
        'passphrase_hash': 1,
        'passphrase_salt': 1,
        'token_hash': 1,
        'token_salt': 1,
        'expiresIn': 1,
        'personal': 1
    })
    docs = await cur.to_list(length=None)
    print('There are ' + str(len(docs)) + ' registered users:')
    for doc in docs:
        click.echo(doc)

@click.group()
def cli():
    pass

@cli.command()
def list():
    db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
    asyncio.run(get_users(db))

if __name__ == '__main__':
    cli()