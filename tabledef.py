import os
from app import User, db

db.drop_all()

db.create_all()

u = User(email="ayebarry@yahoo.com", password="abariba@224", name="Aye Barry", bio="Une Femme Medicine")
db.session.add(u)

u = User(email="mamet@yahoo.com", password="hello@224", name="Mame Thiam", bio="Une Femme Genial")
db.session.add(u)

db.session.commit()

User.query.all()