import vt
import time
import hashlib
from printv import printv
from pprint import pprint
import os
from colorama import Fore, Back, Style
from colorama import just_fix_windows_console

try:
    just_fix_windows_console()
except:
    pass

API_KEY_VIRUSTOTAL = "05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c"

# def scanfile(filepath):
#     client = vt.Client(API_KEY_VIRUSTOTAL)
#     with open(filepath, "rb") as file2scan:
#         bytes = file2scan.read()
#         readablehash = hashlib.sha256(bytes).hexdigest()
#     file = client.get_object(".\\files\\" + str(readablehash))## check if scanned before
#     print(file.last_analysis)
#     with open(filepath, "rb") as file2scan:
#         analysis = client.scan_file(file2scan, wait_for_completion=False)
#         time.sleep(10)
#     print(analysis.status)
#     return

def active_scan_file(filepath, verbosescan=False):
    client = vt.Client(API_KEY_VIRUSTOTAL)
    if not os.path.exists(filepath):
        print("File/filepath does not exist. Exiting.")
        return
    with open(filepath, "rb") as f2scan:
        print("SCANNING FILE WITH VIRUSTOTAL")
        try:
            file_active_scan_analysis = client.scan_file(f2scan, wait_for_completion=True)
            active_scan_file_results = file_active_scan_analysis.get("results")
            mal_sus_reports_file = {}
            for key, val in active_scan_file_results.items():
                if val["category"] == "malicious" or val["category"] == "suspicious":
                    mal_sus_reports_file[key] = val
                else:
                    if verbosescan == True:
                        print(str("\n" + str(key)))
                        for key1, val1 in val.items():
                            print(str(key1) + ": " + str(val1))
            if verbosescan == False:
                print("ONLY MALICIOUS OR SUSPICIOUS REPORTS ARE SHOWN.")
            for key, val in mal_sus_reports_file.items():
                print(str("\n" + str(key)))
                for key1, val1 in val.items():
                    print(Fore.RED + str(key1) + ": " + str(val1) + Fore.WHITE)
            if len(mal_sus_reports_file) == 0:
                print("THIS FILE RAISED NO FLAGS ON VIRUSTOTAL")
        except Exception as e:
            print("Virustotal scan failed")
            printv(e)
    client.close()
    return

def active_scanlink(url2scan, verbosescan = False):
    try:
        client = vt.Client(API_KEY_VIRUSTOTAL)
        active_scan_analysis = client.scan_url(url2scan, wait_for_completion=True)
        client.close()
        active_scan_stats = active_scan_analysis.get("stats")
        active_scan_results = active_scan_analysis.get("results")
        mal_sus_reports = {}
        for key, val in active_scan_results.items():
            if val["category"] == "malicious" or val["category"] == "suspicious":
                mal_sus_reports[key] = val
            else:
                if verbosescan == True:
                    print(str("\n" + str(key)))
                    for key1, val1 in val.items():
                        print(key1 + ": " + val1)
        if verbosescan == False:
            print("ONLY MALICIOUS OR SUSPICIOUS URLS ARE REPORTED.")
        for key, val in mal_sus_reports.items():
            print(str("\n" + str(key)))
            for key1, val1 in val.items():
                print(Fore.RED + key1 + ": " + val1 + Fore.WHITE)

    except Exception as e:
        printv(e)
    return

def scanlink(url, verbosescan = False):
    printv(f"\n{url}")
    try:
        client = vt.Client(API_KEY_VIRUSTOTAL)
        printv("Client object created")
        urlid = vt.url_id(url)
        printv("Urlid created")
        url = client.get_object("/urls/{}".format(urlid))
        printv("RETRIEVED URL SCAN OBJECT")
        printv(f"\n\n[*] LINK REPORT \n\n")
        printv(f"\nNo. of times url submitted: {url.times_submitted}")
        printv(f"\nUrl last analysis stats: \n{url.last_analysis_stats}")
        sus_percent = (int(url.last_analysis_stats['malicious']) +
                            int(url.last_analysis_stats['undetected'])+
                            int(url.last_analysis_stats['suspicious'])) / (int(url.last_analysis_stats['malicious']) + 
                            int(url.last_analysis_stats['undetected']) +
                            int(url.last_analysis_stats['suspicious']) +
                            int(url.last_analysis_stats['harmless'])
                            )
        printv(f"\nReported as Malicious: {url.last_analysis_stats['malicious']}\n")                      
        printv(f'''\nMal percent: {sus_percent}\n''')
        printv("\n\nLINK REPORT END\n\n")
        if verbosescan == True:
            print("\n\n")
            print("LINK LAST ANALYSIS STATS\n")
            for key, val in url.last_analysis_stats.items():
                if key == "malicious" or key == "suspicious" and int(val) > 0:
                    print(Fore.RED + key + ": " + str(val) + Fore.WHITE)
                else:
                    print(key + ": " + str(val))
            print("\n\n")
            pass
    except Exception as e:
        printv(e)
        print("\n\nFAILED TO SCAN LINK. PROCEED WITH CAUTION\n\n")
        client.close()
        return
    client.close()    
    return sus_percent, url.last_analysis_stats['malicious'], url.last_analysis_stats['suspicious']

def domaininfo(domain):
    client = vt.Client(API_KEY_VIRUSTOTAL)

    client.close()
    return

#scanlink("https://www.chess.com/")
# domaininfo("donotreply@isc2.brightspace.com") # use domaininfo function for email scanning