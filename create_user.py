import sys
from app import app
from models import db, User

def create_user(username, password):

    with app.app_context():

        user = User.query.filter_by(username=username).first()

        if user:
            print("User already exists")
            return

        user = User(username=username)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        print("User created successfully")


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage:")
        print("python create_user.py <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    create_user(username, password)
