import pickle
from printv import printv

def execute(emails):
    model = pickle.load(open(".\\resources\\trained_model.sav", 'rb'))
    '''emails = [str]
    It is reccomended to only pass 1 email per execution for readabitly and easier debugging experience'''

    prediction = model.predict(emails)
    pred_percent = model.predict_proba(emails)

    res = "Cannot be determined"
    percent = "Cannot be determined"

    for ind in range(len(list(prediction))):
        p = list(prediction)[ind]

        if p == 'spam':
            res = "It is a spam"
            percent = pred_percent[ind][1] * 100
            print(res, f'Probability: {percent}%')
            continue

        elif p == 'ham':
            res = "It is not a spam"
            percent = pred_percent[ind][0] * 100
            print(res, f'Probability: {percent}%')
            continue