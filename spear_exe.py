import pickle

def execute_model_scan(text):

    # models = [pickle.load(open(r'.\ai_ml\model.sav', 'rb')),
    #     pickle.load(open(r'.\ai_ml\model_1.sav', 'rb')),
    #     pickle.load(open(r'.\ai_ml\model_3.sav', 'rb')),
    #     pickle.load(open(r'.\ai_ml\model_4.sav', 'rb')),
    #     pickle.load(open(r'.\ai_ml\model_5.sav', 'rb')),
    #     pickle.load(open(r'.\ai_ml\model_6.sav', 'rb')),
    # ]
    # '''text = [str]
    # It is reccomended to only pass 1 email per execution for readabitly and easier debugging experience'''
    av_phish_percent = 0
    modelexecutedcount = 0
    for i in range(1,7):
        model = pickle.load(open(f'.\\ai_ml\\model_{i}.sav', 'rb'))
        prediction = model.predict(text)
        pred_percent = model.predict_proba(text)

        res = "Cannot be determined"
        percent = "Cannot be determined"

        for ind in range(len(list(prediction))):
            p = list(prediction)[ind]
            isspampercent = pred_percent[ind][0] * 100
            try:
                av_phish_percent += isspampercent
                modelexecutedcount += 1
            except:
                pass
            print(res, f'Probability of phishing attempt: {(percent)}%')
            if p == 0:
                res = "It is a spam"
                #percent = pred_percent[ind][0] * 100
                #print(res, f'Probability: {round(percent)}%')
                continue

            elif p == 1:
                res = "It is not a spam"
                #percent = pred_percent[ind][1] * 100
                #print(res, f'Probability: {round(percent)}%')
                continue
    av_phish_percent = av_phish_percent / modelexecutedcount
    return av_phish_percent


# email = ['''Subject: You have (3) failed email deliveries
# Sender address: noreply@domain.com
# Sender ip:
# Reply_to:

# ======================================================

# you have (3) failed email deliveries verify your information to deliver your e-mails  brad@malware-traffic-analysis.net  retrieve your mails    please kindly retrieve your email

# ======================================================''']
# execute(email)
