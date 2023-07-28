import pickle

def execute(emails):

    '''emails = [str]
    It is reccomended to only pass 1 email per execution for readabitly and easier debugging experience'''

    total_percent = 0
    spam_count = ham_count = 0

    for i in range(1,7):
        model = pickle.load(open(fr'AASStechclub2324/unselphish/ai_ml/model_{i}.sav', 'rb'))
        prediction = model.predict(emails)
        pred_percent = model.predict_proba(emails)

        print(f"Model {i} running....")

        res = "Cannot be determined"
        percent = "Cannot be determined"

        for ind in range(len(list(prediction))):
            p = list(prediction)[ind]
            percent = pred_percent[ind][0]*100
            total_percent += percent

            if p == 0:
                res = "It is a spam"
                spam_count += 1
                continue

            elif p == 1:
                res = "It is not a spam"
                ham_count += 1
                continue

    av_percent = total_percent/6
    if spam_count > ham_count:
        res = "It is a spam"
    elif ham_count > spam_count:
        res = "It is not a spam"
    else:
        pass

    print(res, f'- Probability: {round(av_percent)}%')
