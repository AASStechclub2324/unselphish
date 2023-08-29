import sctools.emlfilescan as emlscan
import sctools.virustotal as vt
import blacklist_keyword_check as blacklist
# from sctools.# printv import # printv
import re
import sys
import model_exe
import sctools.whatsapp_analysis as whatsapp_analysis
import features.db as db
from features.threat_leaderboard import generate_leaderboard

def scan_link(url2scan):
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
            # printv("\n[+]"+mal_link_report)
            # printv("Should be ALERT!", color='RED')
        if int(stat['malicious'])>0:
            mal_link_report += f"\nUrl: {url2scan}  was found malicous {stat['malicious']} times by various scanners!"
            # printv("\n[+]"+mal_link_report, color='RED')
            mal_found = True
        if int(stat['suspicious']) > 0:
            mal_link_report += f"\nUrl: {url2scan}  was found suspicious {stat['suspicious']} times by various scanners!"
            # printv("\n[+]"+mal_link_report, color='RED')
            sus_found = True
        if int(stat['harmless']) > int(stat['undetected']) + int(stat['malicious']) + int(stat['suspicious']):
            mal_link_report += f"\nUrl: {url2scan}  was found harmless {stat['harmless']} times by various scanners!"
            # printv("\n[+]"+mal_link_report, color="GREEN")
            harmless = True
        

        if not mal_found and not undetected and not sus_found:
            mal_link_report += f"\nUrl: {url2scan}  was not found explicitly malicous!"
            # printv(mal_link_report)

        link_report = f"""
        Initial Scan Report(Votes): {total_votes}

        Deep Scan Report: {analysis_stats}

        {mal_link_report}"""
    
    print(f"Initial Scan Report(Votes): {total_votes}\nDeep Scan Report: {analysis_stats}")
        
    return link_report


def eml_scan(emlfile):
    email_subject, received_from_addr, received_from_ip, reply_to, emailtext, links_in_email = emlscan.parse_eml(emlfile)
    # printv(f"""[+]Sender's Email Address: {received_from_addr}
# \n[+]Sender's IP: {received_from_ip}""")
    report = complete_scan_text([email_subject + " " + emailtext], linklist=links_in_email)
    eml_report = f"""[+]Sender's Email Address: {received_from_addr}
\n[+]Sender's IP: {received_from_ip}
\n[+]Report Form Complete Scan: {report}"""
    
    return eml_report


def single_scan(msg2scan):
    ## Single Message Scan

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

    report = complete_scan_text([msg2scan], links_in_chatmessage)
    # printv(report)
    return report


def whatsapp_scan(chattxt, auth):
    ## whatsapp threat report from txt file

    ################ INITIAL FILTERING OF WHATSAPP MESSAGES #########################
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
    
    msg2scan = []

    for sus in sus_messages:
        if sus["author"] == auth:
            spam_msg = sus["msg"]
            msg2scan.append(spam_msg)

    report = complete_scan_text(msg2scan, linksinchat_all)
    report += f"\n author: {auth}"
    return report
    

def file_scan(fpath):
    f_type, analysis_stats, total_votes, name, size = vt.active_scanfile(fpath)
    stat = eval(str(analysis_stats))
    mal_file_report = ""
    mal_found = False
    sus_found = False
    undetected = False
    harmless = False
    if int(stat['undetected']) > int(stat['harmless']) + int(stat['malicious']) + int(stat['suspicious']):
        undected = True
        mal_file_report += f"\nFile: {name}  was undetected {stat['undetected']} times by various scanners!"

    if int(stat['malicious'])>0:
        mal_file_report += f"\nUrl: {name}  was found malicous {stat['malicious']} times by various scanners!"

        mal_found = True
    if int(stat['suspicious']) > 0:
        mal_file_report += f"\nUrl: {name}  was found suspicious {stat['suspicious']} times by various scanners!"

    if int(stat['harmless']) > int(stat['undetected']) + int(stat['malicious']) + int(stat['suspicious']):
        mal_file_report += f"\nUrl: {name}  was found harmless {stat['harmless']} times by various scanners!"

    

    if not mal_found and not undetected and not sus_found:
        mal_file_report += f"\nFile: {name}  was not found explicitly malicous!"


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

    print("\n[+] SCANNING FOUND LINKS")
    mallinks = []
    suslinks = []
    linksscannedcount = 0
    for link in linklist:
        total_votes, analysis_stats = vt.active_scanlink(link)
        if [total_votes, analysis_stats] == ['err', 'err']:
            mallinks.append(f"Failed to send URL: {link} for analysis and get the report")
            suslinks.append(f"Failed to send URL: {link} for analysis and get the report")
        else:
            stat = eval(str(analysis_stats))
            linksscannedcount += 1
            if int(stat['malicious']) > 0:
                mallinks.append(f"\nLink Reported malicious: {int(stat['malicious'])} times\n" + link)
            if int(stat['suspicious']) > 0:
                suslinks.append(f"\nLink Reported suspicious: {int(stat['suspicious'])} times\n" + link)
    iplist = []
    iplinks = []
    try:
        for line in linklist:
            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
            iplist += ip
            if ip:
                iplinks.append(line)
    except Exception as e:

        print(e)


    rfc_output = model_exe.main_model(text_list)

    mean_rfc, high_rfc, mesg_rfc = rfc_output

    
    #threat index calculation

    index = 10 - int((mean_rfc/100)*9)
        

    ## ALERT PRINTING ######################################################
    blacklist_report = ""
    mallink_alert = ""
    mallink_found = ""
    suslink_found = ""
    ip_report = ""
    if len(blacklistedwords) > 0:

        blacklistedwords = [x.strip() for x in blacklistedwords]

        blacklist_report = f"""\nBlacklisted phrases found {blacklistedwordscnt} times
        \nBlacklisted phrases found:\n {blacklistedwords}
        """
    for i in suslinks:

        suslink_found+=i
    for i in mallinks:

        mallink_found+=i
    if len(mallinks) > 0:
   
        mallink_alert = "\n[**] WARNING!! THIS CONTAINS MALICIOUS ATTACHMENTS/LINKS.\n"
    if len(iplist) > 0:
  
        ip_report = f"\nIP ADDRESSES FOUND IN LINKS (SUSPICIOUS)\n"
        for ip in iplinks:
            # printv(ip, color="RED")
            ip_report+="\n ip"
    
    ## ALERT PRINTING END ######################################################


    ## Generating Threat Report ################################################
    report = f"""
    \n[+] SCANNING FOUND LINKS\n
    \n[+] No. of links scanned: {linksscannedcount}\n
    \n {mallink_alert}\n
    \n Malicious Links: {mallink_found}\n
    \n Suspicious Links: {suslink_found}\n
    \n[+] {blacklist_report}\n
    \n[+] {ip_report}\n
    \n[+] AI prediction percentage of phishing attempt: {mean_rfc}%\n
    \n[+] Maximum phishing percentage of scanned messages: {high_rfc}%\n
          Message: {mesg_rfc}\n
    \n[+] Detected Threat Index: {index}\n
    """

    return report


def update_to_db(choice, report, category):
    ## Database Update ##
    print("Writing to Database....")

    if choice:
        data = {"Category": category, "Report": report}
        db.update_db(data)
    # Database Update End ##

