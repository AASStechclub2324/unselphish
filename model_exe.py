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
        model = pickle.load(open(fr'Spam_Model_RFC.sav', 'rb'))
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




    