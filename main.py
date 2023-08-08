import emlfilescan as emlscan
import virustotallink as vtl
import virustotal as vt2
import blacklist_keyword_check as blacklist
from printv import printv
import re
import requests
from bs4 import BeautifulSoup
import sys
import model_exe
import whatsapp_analysis
import db

def scan_link():
    url2scan = str(input("Url: "))
    url2scan = url2scan.split("?")[0]
    url2scan = url2scan.split(" =")[0]
    url2scan = url2scan.split("#")[0]
    try:
        sus_percent, malcount, suscount = vtl.scanlink(url2scan, verbosescan=True)
        if sus_percent or malcount or suscount:
            activescanbool = str(input("Active scan url (verbose)? (yes/no) default-yes: "))
            if activescanbool.lower().strip() == "yes" or activescanbool.strip() == "":
                verbosescanbool = str(input("Verbose (y/n) default n: "))
                if "y" in verbosescanbool:
                    vtl.active_scanlink(url2scan, verbosescan=True)
                else:
                    print("\nSCANNING URL. THIS MIGHT TAKE A MINUTE.")
                    vtl.active_scanlink(url2scan, verbosescan=False)
            else:
                sys.exit(1)
    except Exception as e:
        printv(e)


def eml_scan():
    emlfile = str(input(".eml file: "))
    email_subject, received_from_addr, received_from_ip, reply_to, emailtext, links_in_email = emlscan.parse_eml(emlfile)
    index = complete_scan_text([email_subject + " " + emailtext], linklist=links_in_email)
    sus_details = []
    if index < 6:
        filepath = r"C:\Users\Anutosh\Desktop\detail.txt"  # Change the file path to your needs
        detail = {"Email Reports": {"Sender's Address": received_from_addr, "Sender's IP": received_from_ip, "threat index": index}}
        sus_details.append(detail)


    with open(filepath, 'w') as file:
        file.write(str(sus_details))
    db.update_storage(filepath)


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

    index = complete_scan_text([msg2scan])



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
    print(sus_messages)
    ## Database Update ##
    details = []
    auth = input("\nEnter message author to be scanned: ")
    msg2scan = []

    for sus in sus_messages:
        if sus["author"] == auth:
            spam_msg = sus["msg"]
            msg2scan.append(spam_msg)

    index = complete_scan_text(msg2scan, linksinchat_all)
    if index < 6:
        filepath = r"C:\Users\Anutosh\Desktop\detail.txt"  # Change the file path to your needs
        detail = {"Whatsapp Reports": {'author': str(auth), 'threat index': index}}
        details.append(detail)


    with open(filepath, 'a') as file:
        file.write(str(details))
    # db.update_storage(filepath)
    ## Database Update End ##
    

def file_scan():
    fpath = str(input("Filepath of file to scan: "))
    vt2.active_scan_file(fpath)


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
        try:
            sus_percent, malcount, suscount = vt2.active_scanlink(link)
            linksscannedcount += 1
            if malcount > 0:
                mallinks.append(f"\nLink Reported malicious: {malcount} times\n" + link)
            if suscount > 0:
                suslinks.append(f"\nLink Reported suspicious: {suscount} times\n" + link)
        except Exception as e:
            printv(e)
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
    # printv(links_in_email)
    # url1 = "http://www.webconfs.com/domain-age.php"
    # for url in links_in_email:

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
    if len(blacklistedwords) > 0:
        printv(f"\nVIRUSTOTAL SCAN RESULTS", color="RED")
        printv(f"\nBlacklisted phrases found {blacklistedwordscnt} times", color="RED")
        printv(f"\nBlacklisted phrases found:\n", color="RED")
        blacklistedwords = [x.strip() for x in blacklistedwords]
        printv(blacklistedwords, color="RED")
    for i in suslinks:
        printv(i, color="RED")
    for i in mallinks:
        printv(i, color="RED")
    if len(mallinks) > 0:
        printv("\n[**] WARNING!! THIS CONTAINS MALICIOUS ATTACHMENTS/LINKS.\n", color="RED")
    if len(iplist) > 0:
        printv("\nIP ADDRESSES FOUND IN LINKS (SUSPICIOUS)\n", color="RED")
        for ip in iplinks:
            printv(ip, color="RED")
    
    ## ALERT PRINTING END ######################################################


    ## Generating Threat Report ################################################

    return index


################# Executable for CLI tool #######################

if __name__ == "__main__":

    try:
        scantype = int(input('''1. Scan link (virustotal)\n2. Threat report from downloaded email (.eml)\n3. Scan singular message\n4. Threat report from exported whatsapp chat \n5. Scan file (virustotal)\n\nOption: '''))
    except:
        sys.exit(1)

    if scantype == 1:
        scan_link()

    if scantype == 2:
        eml_scan()
        
    if scantype == 3:
        single_scan()

    if scantype == 4:
        whatsapp_scan



    if scantype == 5:
        file_scan()