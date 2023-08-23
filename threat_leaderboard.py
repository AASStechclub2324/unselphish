import db

def generate_leaderboard():
    chain = db.load_db()
    return chain



if __name__ == "__main__":
    details = generate_leaderboard()

