import firebase_admin
from firebase_admin import credentials
from firebase_admin import storage

cred = credentials.Certificate(r"")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'unselphish.appspot.com'
})

bucket = storage.bucket()

def update_storage(filename):
    blob = bucket.blob(filename)
    blob.upload_from_filename(filename)



