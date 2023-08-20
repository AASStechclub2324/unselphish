import db

def generate_leaderboard():
    db.retrieve_data(r"resources\downloaded_details.txt")

    with open(r"resources\downloaded_details.txt") as dd:
        details = dd.readlines()
        # print(details)
    
    return details


if __name__ == "__main__":
    details = generate_leaderboard()

