import emlfilescan as emlscan
import virustotal as vt
import blacklist_keyword_check as blacklist
from printv import printv
import re
import sys
import model_exe
import whatsapp_analysis
import db

def scan_link():
    url2scan = str(input("Url: "))
    print("\nSCANNING URL. THIS MIGHT TAKE A MINUTE.")
    total_votes, analysis_stats = vt.active_scanlink(url=url2scan)
    if [total_votes, analysis_stats] == ['err', 'err']:
        link_report = f"Failed to send URL: {url2scan} for analysis and get the report"
    else:
        stat = eval(analysis_stats)
        mal_link_report = ""
        mal_found = False
        sus_found = False
        undetected = False
        harmless = False
        if int(stat['undetected']) > int(stat['harmless']) + int(stat['malicious']) + int(stat['suspicious']):
            undetected = True
            mal_link_report += f"\nUrl: {url2scan}  was undetected {stat['undetected']} times by various scanners!"
            printv("\n[+]"+mal_link_report)
            printv("Should be ALERT!", color='RED')
        if int(stat['malicious'])>0:
            mal_link_report += f"\nUrl: {url2scan}  was found malicous {stat['malicious']} times by various scanners!"
            printv("\n[+]"+mal_link_report, color='RED')
            mal_found = True
        if int(stat['suspicious']) > 0:
            mal_link_report += f"\nUrl: {url2scan}  was found suspicious {stat['suspicious']} times by various scanners!"
            printv("\n[+]"+mal_link_report, color='RED')
            sus_found = True
        if int(stat['harmless']) > int(stat['undetected']) + int(stat['malicious']) + int(stat['suspicious']):
            mal_link_report += f"\nUrl: {url2scan}  was found harmless {stat['harmless']} times by various scanners!"
            printv("\n[+]"+mal_link_report, color="GREEN")
            harmless = True
        

        if not mal_found and not undetected and not sus_found:
            mal_link_report += f"\nUrl: {url2scan}  was not found explicitly malicous!"
            printv(mal_link_report)

        link_report = f"""
        Initial Scan Report(Votes): {total_votes}

        Deep Scan Report: {analysis_stats}

        {mal_link_report}"""
    
    print(f"Initial Scan Report(Votes): {total_votes}\nDeep Scan Report: {analysis_stats}")
        
    return link_report


def eml_scan():
    emlfile = str(input(".eml file: "))
    email_subject, received_from_addr, received_from_ip, reply_to, emailtext, links_in_email = emlscan.parse_eml(emlfile)
    index, report = complete_scan_text([email_subject + " " + emailtext], linklist=links_in_email)
    sus_details = []
    # if index < 6:
    #     filepath = r"C:\Users\Anutosh\Desktop\detail.txt"  # Change the file path to your needs
    #     detail = {"Email Reports": {"Sender's Address": received_from_addr, "Sender's IP": received_from_ip, "threat index": index}}
    #     sus_details.append(detail)


    # with open(filepath, 'w') as file:
    #     file.write(str(sus_details))
    # db.update_storage(filepath)
    return index, report


def single_scan():
    ## Single Message Scan
    msg2scan = str(input("Text message to scan: "))

    ## Extracting links before replacing them
    links_in_chatmessage = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',msg2scan)

    #################################### DATA CLEANING ######################################

    #CONVRTING EVERYTHING TO LOWERCASE
    msg2scan=msg2scan.lower()

    #REPLACING NEXT LINES BY 'WHITE SPACE'
    msg2scan=msg2scan.replace(r'\n'," ") 

    # REPLACING EMAIL IDs BY 'MAILID'
    msg2scan=msg2scan.replace(r'^.+@[^\.].*\.[a-z]{2,}$','MailID')

    # REPLACING URLs  BY 'Links'
    msg2scan=msg2scan.replace(r'^http\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?$','Links')

    # REPLACING CURRENCY SIGNS BY 'MONEY'
    msg2scan=msg2scan.replace(r'£|\$', 'Money')

    # REPLACING LARGE WHITE SPACE BY SINGLE WHITE SPACE
    msg2scan=msg2scan.replace(r'\s+', ' ')

    # REPLACING LEADING AND TRAILING WHITE SPACE BY SINGLE WHITE SPACE
    msg2scan=msg2scan.replace(r'^\s+|\s+?$', '') 

    #REPLACING CONTACT NUMBERS
    msg2scan=msg2scan.replace(r'^\(?[\d]{3}\)?[\s-]?[\d]{3}[\s-]?[\d]{4}$','contact number')

    #REPLACING SPECIAL CHARACTERS  BY WHITE SPACE 
    msg2scan=msg2scan.replace(r"[^a-zA-Z0-9]+", " ")

    #################################### DATA CLEANING END ######################################

    index, report = complete_scan_text([msg2scan])
    printv(report)
    return index, report


def whatsapp_scan():
    ## whatsapp threat report from txt file

    ################ INITIAL FILTERING OF WHATSAPP MESSAGES #########################
    chattxt = str(input("Filepath of whatsapp chat file(.txt): "))
    parsedchat_authors, parsedchat_messages = whatsapp_analysis.parse_chat_file(chattxt)
    sus_messages = []
    chatblacklistedwordsfoundall = []
    linksinchat_all = []
    for message in parsedchat_messages:
        chatblacklistedwords, chatblacklistedcount = blacklist.check_blacklisted_keywords(message)
        if chatblacklistedcount > 0:
            author = parsedchat_authors[list(parsedchat_messages).index(message)]
            msg_detail = {"author": author, "msg": message}
            sus_messages.append(msg_detail)
            chatblacklistedwordsfoundall += chatblacklistedwords
        links_in_chatmessage = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',message)
        linksinchat_all += links_in_chatmessage
    #### INITIAL FILTERING END #########################
    ## Database Update ##
    details = []
    auth = input("\nEnter message author to be scanned: ")
    msg2scan = []

    for sus in sus_messages:
        if sus["author"] == auth:
            spam_msg = sus["msg"]
            msg2scan.append(spam_msg)

    index, report = complete_scan_text(msg2scan, linksinchat_all)
    # if index < 6:
    #     filepath = r"C:\Users\Anutosh\Desktop\detail.txt"  # Change the file path to your needs
    #     detail = {"Whatsapp Reports": {'author': str(auth), 'threat index': index}}
    #     details.append(detail)


    # with open(filepath, 'a') as file:
    #     file.write(str(details))
    # db.update_storage(filepath)
    ## Database Update End ##
    return index, report
    

def file_scan():
    fpath = str(input("Filepath of file to scan: "))
    f_type, analysis_stats, total_votes, name, size = vt.active_scan_file(fpath)
    stat = eval(analysis_stats)
    mal_file_report = ""
    mal_found = False
    sus_found = False
    undetected = False
    harmless = False
    if int(stat['undetected']) > int(stat['harmless']) + int(stat['malicious']) + int(stat['suspicious']):
        undected = True
        mal_file_report += f"File: {name}  was undetected {stat['undetected']} times by various scanners!"
        printv("\n[+]"+mal_file_report)
        printv("Should be ALERT!", color='RED')
    if int(stat['malicious'])>0:
        mal_file_report += f"Url: {name}  was found malicous {stat['malicious']} times by various scanners!"
        printv("\n[+]"+mal_file_report, color='RED')
        mal_found = True
    if int(stat['suspicious']) > 0:
        mal_file_report += f"Url: {name}  was found suspicious {stat['suspicious']} times by various scanners!"
        printv("\n[+]"+mal_file_report, color='RED')
    if int(stat['harmless']) > int(stat['undetected']) + int(stat['malicious']) + int(stat['suspicious']):
        mal_file_report += f"Url: {name}  was found harmless {stat['harmless']} times by various scanners!"
        printv("\n[+]"+mal_file_report, color="GREEN")
    

    if not mal_found and not undetected and not sus_found:
        mal_file_report = f"File: {name}  was not found explicitly malicous!"
        printv(mal_file_report)

    file_report = f"""Virustotal Scan Report:
    \n[+]File Name: {name}
    \n[+]File Type: {f_type}
    \n[+]File Size: {size} 
    \n[+]{mal_file_report}"""
    return file_report


def complete_scan_text(text_list=[], linklist=[]):

    #vtscan links
    #blacklist word scan
    #aiml model scan of text pattern for spear phishing
    text = ''.join(text_list)
    
    blacklistedwords, blacklistedwordscnt = blacklist.check_blacklisted_keywords(text)
    if len(linklist) == 0:
        linklist = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',text)
    printv("")
    print("\n[+] SCANNING FOUND LINKS")
    mallinks = []
    suslinks = []
    linksscannedcount = 0
    for link in linklist:
        if [total_votes, analysis_stats] == ['err', 'err']:
            mallinks.append(f"Failed to send URL: {link} for analysis and get the report")
            suslinks.append(f"Failed to send URL: {link} for analysis and get the report")
        else:
            total_votes, analysis_stats = vt.active_scanlink(link)
            stat = eval(analysis_stats)
            linksscannedcount += 1
            if int(stat['malicious']) > 0:
                mallinks.append(f"\nLink Reported malicious: {int(stat['malicious'])} times\n" + link)
            if int(stat['suspicious']) > 0:
                suslinks.append(f"\nLink Reported suspicious: {int(stat['suspicious'])} times\n" + link)
    printv()

    printv(f"\n[+] No. of links scanned: {linksscannedcount}")
    iplist = []
    iplinks = []
    try:
        for line in linklist:
            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
            iplist += ip
            if ip:
                iplinks.append(line)
    except Exception as e:
        printv(e)


    spear_output, svm_output = model_exe.main_model(text_list)
    mean_spear, high_spear, mesg_spear = spear_output
    mean_svm, high_svm, mesg_svm = svm_output
    error = (abs(mean_spear-mean_svm)/mean_svm) * 100
    #threat index calculation
    printv(f"AI prediction percentage of phishing attempt: {mean_spear}%")
    index = 10 - int((mean_spear/100)*9)
    # if error <= 10:
    #     index = 10 - int((mean_spear/100)*9)
    #     printv(f"AI prediction percentage of phishing attempt: {mean_spear}%")
    # else:
    #     printv(f"\nModel couldn't analyze text.\n", color='red')

        

    ## ALERT PRINTING ######################################################
    blacklist_report = ""
    mallink_alert = ""
    mallink_found = ""
    suslink_found = ""
    ip_report = ""
    if len(blacklistedwords) > 0:
        printv(f"\nVIRUSTOTAL SCAN RESULTS", color="RED")
        printv(f"\nBlacklisted phrases found {blacklistedwordscnt} times", color="RED")
        printv(f"\nBlacklisted phrases found:\n", color="RED")
        blacklistedwords = [x.strip() for x in blacklistedwords]
        printv(blacklistedwords, color="RED")
        blacklist_report = f"""\nBlacklisted phrases found {blacklistedwordscnt} times
        \nBlacklisted phrases found:\n {blacklistedwords}
        """
    for i in suslinks:
        printv(i, color="RED")
        suslink_found+=i
    for i in mallinks:
        printv(i, color="RED")
        mallink_found+=i
    if len(mallinks) > 0:
        printv("\n[**] WARNING!! THIS CONTAINS MALICIOUS ATTACHMENTS/LINKS.\n", color="RED")
        mallink_alert = "\n[**] WARNING!! THIS CONTAINS MALICIOUS ATTACHMENTS/LINKS.\n"
    if len(iplist) > 0:
        printv("\nIP ADDRESSES FOUND IN LINKS (SUSPICIOUS)\n", color="RED")
        ip_report = f"\nIP ADDRESSES FOUND IN LINKS (SUSPICIOUS)\n"
        for ip in iplinks:
            printv(ip, color="RED")
            ip_report+="\n ip"
    
    ## ALERT PRINTING END ######################################################


    ## Generating Threat Report ################################################
    report = f"""
    \n[+] SCANNING FOUND LINKS
    \n[+] No. of links scanned: {linksscannedcount}
    \n {mallink_alert}
    \n Malicious Links: {mallink_found}
    \n Suspicious Links: {suslink_found}
    \n[+] {blacklist_report}
    \n[+] {ip_report}
    \n[+] AI prediction percentage of phishing attempt: {mean_spear}%
    \n[+] Maximum phishing percentage of scanned messages: {high_spear}%
          Message: {mesg_spear} 
    """

    return index, report


def update_to_db(choice, report):
    ## Database Update ##
    print("Writing to Database....")
    details = []
    if choice:
        filepath = r"resources\spam_details.txt"  # Change the file path to your needs
        details.append(report)

    with open(filepath, 'a') as file:
        file.write(str(details))
    db.update_storage(filepath)
    # Database Update End ##



################# Executable for CLI tool #######################

if __name__ == "__main__":

    try:
        scantype = int(input('''1. Scan link (virustotal)\n2. Threat report from downloaded email (.eml)\n3. Scan singular message\n4. Threat report from exported whatsapp chat \n5. Scan file (virustotal)\n\nOption: '''))
    except:
        sys.exit(1)

    if scantype == 1:
        report = scan_link()

    if scantype == 2:
        index, report = eml_scan()
        
    if scantype == 3:
        index, report = single_scan()

    if scantype == 4:
        index, report = whatsapp_scan()

    if scantype == 5:
        report = file_scan()
    
    try:
        update_choice = input("Submit to database?[yes/no], Default = no:  ")
        if update_choice.lower() == 'yes' or update_choice.lower() == 'y':
            update_to_db(True, report)
        else:
            pass
    except:
        sys.exit(1)
