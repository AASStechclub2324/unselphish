import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
# from firebase_admin import storage

# cred = credentials.Certificate(r"")
# firebase_admin.initialize_app(cred, {
#     'storageBucket': 'unselphish.appspot.com'
# })

# bucket = storage.bucket()

# def update_storage(filename):
#     blob = bucket.blob(filename)
#     blob.upload_from_filename(filename)


cred = credentials.Certificate(r"C:\Users\Anutosh\Unselphish-root\Unselphish\firebase-adminsdk-gmw7s-ffb62dd9c5.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://unselphish-default-rtdb.asia-southeast1.firebasedatabase.app'
})
db_ref = db.reference()

# Set up Firebase project credentials
firebase_api_key = "AIzaSyCz1uLRuRFkQUo4yfj2Xy7nB5JZgVHnp4A"
firebase_project_id = "unselphish"


def load_db():
    chain = []
    ids = []
    db_ref = db.reference('user_blocks')
    threats_data = db_ref.get()
    if threats_data:
        for id in threats_data:
            threat_data = threats_data[id]
            chain.append(threat_data)
            ids.append(id)
    else:
        pass

    return chain


def update_db(report: dict):
    db_ref.child("user_blocks").push(report)
    