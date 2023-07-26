import os
from bs4 import BeautifulSoup
import json
import datetime
import eml_parser
from pprint import pprint
from email import policy, message_from_file
from email.parser import Parser
import re
from printv import printv

def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial

def parse_eml(eml_file):
    # with open(eml_file, "r", errors="ignore") as f:
        # lines = f.readlines()
        # return_path = ""
        # received_from_ip = ""
        # received_from_dns = ""
        # email_subject = ""
        # sender_email_addr = ""
        # try:
        #     return_path = str([x for x in lines if x.startswith("Return-Path:")][0].split(": <")[1].strip()[:-1])
        # except Exception as e:
        #     print(e)
        # try:
        #     received_from_ip = str([x for x in lines if x.startswith("Received: from [")][0].split("[")[1].split("]")[0])
        # except Exception as e:
        #     print(e)
        # try:
        #     received_from_dns = str([x for x in lines if x.startswith("Received: from")][0].split(" ")[2])
        # except Exception as e:
        #     print(e)
        # try:
        #     email_subject = str(" ".join([x for x in lines if x.startswith("Subject:")][0].split(" ")[1:])).strip()
        # except Exception as e:
        #     print(e)
        # try:
        #     sender_email_addr = str([x for x in lines if x.startswith("From: \"")][0].split(" ")[1].strip("\""))
        # except Exception as e:
        #     print(e)
        
        # xmlcode = str()
        # links_in_email = []
        # email_text = ""

        # try:
        #     foundxml = False
        #     for x in lines:
        #         if x.startswith("<?xml"):
        #             xmlcode += x
        #             foundxml = True
        #         elif foundxml == True:
        #             xmlcode += x
        #     # print(xmlcode)
        #     with open(".\\temp\\tempemail.html", "w") as hf:
        #         hf.write(xmlcode)

        #     links_in_email = [link.get('href') for link in BeautifulSoup(xmlcode, 'html.parser').find_all('a')]
        #     #print(links_in_email)

        #     email_text = BeautifulSoup(xmlcode, 'html.parser').get_text()
        #     #print(email_text)
            
        #     if os.path.exists(".\\temp\\tempemail.html"):
        #         os.remove(".\\temp\\tempemail.html")
        
        # except Exception as e:
        #     print(e)
            
        # print(return_path)
        # print(received_from_ip)
        # print(received_from_dns)
        # print(email_subject)
        # print(sender_email_addr)

    email_subject = ""
    received_from_addr = ""
    received_from_ip = ""
    reply_to = ""

    with open(eml_file, "rb") as efile:
        raw_email = efile.read()
    ep = eml_parser.EmlParser()
    parsed_eml = ep.decode_email_bytes(raw_email)

    jsondat = json.dumps(parsed_eml, default=json_serial, indent=2)
    emldat = json.loads(jsondat)
    # with open("rep.json", "w") as f:
    #     f.write(jsondat)
    try:
        email_subject = emldat["header"]["subject"].strip()
    except:
        pass
    try:
        received_from_addr = emldat["header"]["from"].strip()
    except:
        pass
    try:
        received_from_ip = emldat["header"]["received"][2]["from"][0].strip()
    except:
        pass
    try:
        reply_to = emldat["header"]["header"]["reply-to"][0].strip()
    except:
        pass
    printv()
    printv("Subject: " + email_subject)
    printv("Sender address: " + received_from_addr)
    printv("Sender ip: " + received_from_ip)
    printv("Reply_to: " + reply_to)

    emailtext = ""

    with open(eml_file, errors="ignore") as efile:
        parser = Parser()
        msg = parser.parse(efile)
        text_content = []
        for part in msg.walk():
            if part.get_content_type().startswith('text/plain'):
                text_content.append(part.get_payload())
        emailtext = "".join(text_content)

        if emailtext.strip() == "":
            with open(eml_file, "r", errors="ignore") as f1:
                lines = f1.readlines()
                xmlcode = str()
                try:
                    foundxml = False
                    for x in lines:
                        if x.startswith("<?xml") or x.startswith("<HTML") or x.lower().startswith("<html") or x.startswith("<!DOCTYPE html"):
                            xmlcode += x
                            foundxml = True
                        elif foundxml == True:
                            xmlcode += x
                    # print(xmlcode)
                    with open(".\\temp\\tempemail.html", "w") as hf:
                        hf.write(xmlcode)

                    #print(links_in_email)

                    emailtext = BeautifulSoup(xmlcode, 'html.parser').get_text().strip()
                    #print(email_text)
                    
                    if os.path.exists(".\\temp\\tempemail.html"):
                        os.remove(".\\temp\\tempemail.html")
                
                except Exception as e:
                    printv(str(e))
        try:
            links_in_email = [link.get('href') for link in BeautifulSoup(xmlcode, 'html.parser').find_all('a')]
        except:
            links_in_email = []

        links_in_email += re.findall(r'\<.*?\>', "".join(emailtext.split("\n")))
        links_in_email += re.findall(r'\(.*?\)', "".join(emailtext.split("\n")))
        # links_in_email += re.findall(r'(https?://[^\s]+)', emailtext)
        for i in range(len(links_in_email)):
            #print(f"Modifying tag links {links_in_email[i]}")
            try:
                links_in_email[i] = links_in_email[i].strip("(").strip(")")
                links_in_email[i] = links_in_email[i].strip("<").strip(">")
                links_in_email[i] = links_in_email[i].split("?")[0]
                links_in_email[i] = links_in_email[i].split(" =")[0]
                links_in_email[i] = links_in_email[i].split("#")[0]
            except Exception as e:
                printv(e)
        links_in_email = set(links_in_email)
        printv("\n======================================================\n")
        # printv(emailtext)
        printv(" ".join(emailtext.lower().strip().split("\n")))
        printv("\n======================================================\n")
        printv("[+] LINKS FOUND: ")
        # print(links_in_email)
        for i in links_in_email:
            printv(i)
        printv("")

    #os.system(f"eml-extractor ")

    return email_subject, received_from_addr, received_from_ip, reply_to, emailtext, links_in_email
    #return return_path, received_from_ip, received_from_dns, email_subject, sender_email_addr, links_in_email, email_text, xmlcode, jsondat

# parse_eml(".\\eml_files\\Welcome to your Getting Started series.eml")