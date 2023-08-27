import features.db as db

def generate_leaderboard():
    chain = db.load_db()
    return chain


if __name__ == "__main__":
    details = generate_leaderboard()
    print(details)
    print("\n")
    print('\n')
    detail_list = []
    for detail in details:
        category = detail['Category']
        report = detail['Report']
        report = report.splitlines()
        output = [f'Category: {category}']
        output.extend(report)
        detail_list.append(output)
    print(detail_list)

