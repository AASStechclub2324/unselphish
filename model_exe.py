import pickle


def execute_spear_models(text):
    all_percent = []
    print("ML Models runnning......")
    for index in range(len(text)):
        msg = text[index]
        msg = [msg]
        total_percent = 0
        spam_count = 0
        ham_count = 0

        for i in range(1,5):
            model = pickle.load(open(fr'ai_ml/spear_models/model_{i}.sav', 'rb'))
            
            prediction = model.predict(msg)
            pred_percent = model.predict_proba(msg)
            percent = pred_percent[0][0]*100
            print(percent)

            #total percent of all the models predicting one message
            total_percent += percent

            if prediction == 0:
                res = "It is a spam"
                spam_count += 1
                continue

            elif prediction == 1:
                res = "It is not a spam"
                ham_count += 1
                continue
        avg_percent = total_percent/6
        all_percent.append(avg_percent)
        if spam_count > ham_count:
            res = "It is a spam"
        elif ham_count > spam_count:
            res = "It is not a spam"
        else:
            pass
    #mean percent of all messages
    mean_percent = sum(all_percent)/len(all_percent)
    highest = max(all_percent)
    high_msg = text[all_percent.index(highest)]
    print(all_percent)

    return mean_percent, highest, high_msg

def execute_spam_models(text):
    print("ML Models Running....")
    all_percent = []
    for ind in range(len(text)):
        msg = text[ind]
        msg = [msg]
        model = pickle.load(open(fr'ai_ml/Spam_Model_RFC.sav', 'rb'))
        prediction = model.predict(msg)
        pred_percent = model.predict_proba(msg)
        percent = pred_percent[0][1]*100
        all_percent.append(percent)
    
    print("Generating Report Of AI Analysis....")

    mean_percent =  sum(all_percent)/len(all_percent)

    highest = max(all_percent)
    high_msg = text[all_percent.index(highest)]
    return mean_percent, highest, high_msg



def main_model(input_var):
    # return execute_spear_models(input_var), execute_spam_models(input_var)
    return execute_spam_models(input_var)  # We are not using spear_models because RFC is strong enough and also faster



if __name__ == '__main__':
    emails = ['your microsoft account has been compromised ,you must update before or else your account going to close click to update', 'Today we want to inform you that the application period for 15.000 free Udacity Scholarships in Data Science is now open! Please apply by November 16th, 2020 via https://www.udacity.com/bertelsmann-tech-scholarships.']
    lebu = ["Guess what? You have been shortlisted to win a free HP Laptop. It is a one-time oppurtunity. Don't miss this!! Txt on 9876543234 to claim your reward", "Alert!! Win a free Apple watch today. Call at 0987657654 to claim your reward. Hurry! Don't Miss this one-time opportunity!!"]
    test = ['''Subject: You have (3) failed email deliveries
    Sender address: noreply@domain.com
    Sender ip:
    Reply_to:

    ======================================================

    you have (3) failed email deliveries verify your information to deliver your e-mails  brad@malware-traffic-analysis.net  retrieve your mails    please kindly retrieve your email

    ======================================================''']
    input_var = [lebu[0]]
    print(main_model(input_var))
    print("\n"+"-"*50)

    input_var = [lebu[1]]
    print(main_model(input_var))
    print("\n"+"-"*50)

    input_var = [emails[1]]
    print(main_model(input_var))
    print("\n"+"-"*50)

    input_var = [emails[0]]
    print(main_model(input_var))
    print("\n"+"-"*50)

    input_var = test
    print(main_model(input_var))
    print("\n"+"-"*50)



    