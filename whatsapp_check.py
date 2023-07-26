import emlfilescan as emlscan
import virustotallink as vtl
import blacklist_keyword_check as blacklist
from printv import printv
import re
import requests
from bs4 import BeautifulSoup
import sys


filename = str(input('.txt file: '))
with open(fr'{filename}') as f:
    msg = f.read()
    received_from_addr, received_from_ip, reply_to, text, links_in_txt = emlscan.parse_eml(msg)
    blacklistedwords, blacklistedwordscnt = blacklist.check_blacklisted_keywords(text)
    printv("")
    print("\n[+] SCANNING FOUND LINKS")
    txtlinks = []
    suslinks = []
    linksscannedcount = 0
    for link in links_in_txt:
        try:
            sus_percent, malcount, suscount = vtl.scanlink(link)
            linksscannedcount += 1
            if malcount > 0:
                txtlinks.append(f"\nLink Reported malicious: {malcount} times\n" + link)
            if suscount > 0:
                suslinks.append(f"\nLink Reported suspicious: {suscount} times\n" + link)
        except Exception as e:
            printv(e)
    printv()
    
    printv(f"\n[+] No. of links scanned: {linksscannedcount}")
    iplist = []
    iplinks = []
    try:
        for line in links_in_email:
            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
            iplist += ip
            if ip:
                iplinks.append(line)
    except Exception as e:
        printv(e)
    # printv(links_in_email)
    # url1 = "http://www.webconfs.com/domain-age.php"
    # for url in links_in_email:
        

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
        printv("\n[**] WARNING!! THIS EMAIL CONTAINS MALICIOUS ATTACHMENTS/LINKS.\n", color="RED")
    if len(iplist) > 0:
        printv("\nIP ADDRESSES FOUND IN LINKS (SUSPICIOUS)\n", color="RED")
        for ip in iplinks:
            printv(ip, color="RED")
    
    ## ALERT PRINTING END ######################################################

