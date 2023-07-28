import firebase_admin
from firebase_admin import credentials
from firebase_admin import storage

cred = credentials.Certificate(r"C:\Users\USER\Desktop\Spam_recognition\database\unselphish-firebase-adminsdk-gmw7s-d6bc0bb794.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'unselphish.appspot.com'
})

bucket = storage.bucket()

def update_storage(filename):
    blob = bucket.blob(filename)
    blob.upload_from_filename(filename)



