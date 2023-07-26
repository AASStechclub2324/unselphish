import yara
import glob
from printv import printv
import os

def load_rules():
    rules_dir = ".\\resources\\yararules\\" #https://github.com/advanced-threat-research/Yara-Rules/tree/master
    aptrulesdir = rules_dir + "APT\\"
    malwarerulesdir = rules_dir + "malware\\"
    minersrulesdir = rules_dir + "miners\\"
    ransomwarerulesdir = rules_dir + "ransomware\\"
    stealerrulesdir = rules_dir + "stealer\\"
    all_rules = []
    for rulefile in glob.glob(aptrulesdir + r"*.yar"):
        try:
            rules = yara.compile(rulefile)
            all_rules.append(rules)
        except Exception as e:
            printv(e)
    for rulefile in glob.glob(malwarerulesdir + r"*.yar"):
        try:
            rules = yara.compile(rulefile)
            all_rules.append(rules)
        except Exception as e:
            printv(e)
    for rulefile in glob.glob(minersrulesdir + r"*.yar"):
        try:
            rules = yara.compile(rulefile)
            all_rules.append(rules)
        except Exception as e:
            printv(e)
    for rulefile in glob.glob(ransomwarerulesdir + r"*.yar"):
        try:
            rules = yara.compile(rulefile)
            all_rules.append(rules)
        except Exception as e:
            printv(e)
    for rulefile in glob.glob(stealerrulesdir + r"*.yar"):
        try:
            rules = yara.compile(rulefile)
            all_rules.append(rules)
        except Exception as e:
            printv(e)
    printv(all_rules)
    printv("\n\nSaving compiled rules to file\n")
    for rule in all_rules:
        rule.save(f".\\resources\\compiledrules\\{str(rule)}.rule")
    return all_rules

def scan_file_yara(filepath):
    if not os.path.exists(filepath):
        print("File/filepath does not exist")
        return
    
    return

load_rules()