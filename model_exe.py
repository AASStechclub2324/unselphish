import pickle
def execute(emails):
    model = pickle.load(open(r'.\ai_ml\trained_model.sav', 'rb'))
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
            print(res, f'Probability: {round(percent)}%')
            continue

        elif p == 'ham':
            res = "It is not a spam"
            percent = pred_percent[ind][0] * 100
            print(res, f'Probability: {round(percent)}%')
            continue

    return round(percent)

# email = ['''Subject: You have (3) failed email deliveries
# Sender address: noreply@domain.com
# Sender ip:
# Reply_to:

# ======================================================

# you have (3) failed email deliveries verify your information to deliver your e-mails  brad@malware-traffic-analysis.net  retrieve your mails    please kindly retrieve your email

# ======================================================''']
# execute(email, model)