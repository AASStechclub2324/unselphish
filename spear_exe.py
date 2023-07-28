import pickle

emails = ['your microsoft account has been compromised ,you must update before or else your account going to close click to update', 'Today we want to inform you that the application period for 15.000 free Udacity Scholarships in Data Science is now open! Please apply by November 16th, 2020 via https://www.udacity.com/bertelsmann-tech-scholarships.']
input_var = ["Guess what? You have been shortlisted to win a free HP Laptop. It is a one-time oppurtunity. Don't miss this!! Txt on 9876543234 to claim your reward", "Alert!! Win a free Apple watch today. Call at 0987657654 to claim your reward. Hurry! Don't Miss this one-time opportunity!!"]
test = ['''Subject: You have (3) failed email deliveries
Sender address: noreply@domain.com
Sender ip:
Reply_to:

======================================================

you have (3) failed email deliveries verify your information to deliver your e-mails  brad@malware-traffic-analysis.net  retrieve your mails    please kindly retrieve your email

======================================================''']

def execute(emails):

    '''emails = [str]
    It is reccomended to only pass 1 email per execution for readabitly and easier debugging experience'''

    total_percent = 0
    spam_count = ham_count = 0

    for i in range(1,7):
        model = pickle.load(open(fr'C:\Users\Anutosh\Desktop\Spam_recognition\spear phishing detector\model_{i}.sav', 'rb'))
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


input_var = test

execute(input_var)

