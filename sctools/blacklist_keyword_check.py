from printv import printv

def check_blacklisted_keywords(text):
    blacklisted_terms = []
    with open(r"resources\blacklist.txt", "r") as blklist:
        blacklisted_terms = blklist.readlines()
    for i in range(len(blacklisted_terms)):
        blacklisted_terms[i] = blacklisted_terms[i].lower().strip("\n").strip()
        #printv(blacklisted_terms)
    #print(blacklisted_terms)
    text = " ".join(text.lower().strip().split("\n"))
    wrd_cnt = 0
    blacklisted_terms_matched = []
    for i in blacklisted_terms:
        if i.lower() in text:
            wrd_cnt += 1
            blacklisted_terms_matched.append(i)
    return blacklisted_terms_matched, wrd_cnt