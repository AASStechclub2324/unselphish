import virustotal_python
from printv import printv
import os
from base64 import urlsafe_b64encode
import hashlib
import requests

def active_scanlink(url):
    with virustotal_python.Virustotal("05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c") as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            
            # Safe encode URL in base64 format
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

            report = vtotal.request(f"urls/{url_id}")
            total_votes = report.data['attributes']['total_votes']
            last_analysis_stats = report.data['attributes']['last_analysis_stats']



        except virustotal_python.VirustotalError as err:
            print(f"Failed to send URL: {url} for analysis and get the report: {err}")
    return total_votes, last_analysis_stats

def active_scandomain(url):
    with virustotal_python.Virustotal("05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c") as vtotal:
        resp = vtotal.request(f"domains/{url}")
        printv(resp.data)

def active_scanfile(filepath):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': "05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c"}

    files = {"file": (os.path.basename(filepath), open(os.path.abspath(filepath), "rb"))}

    resp = requests.post(url, files=files, params=params)
    print(resp.json())
    with virustotal_python.Virustotal("05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c") as vtotal:
        file_id = resp.json()['sha1']
        report = vtotal.request(f"files/{file_id}")
        print(report.data)


        # resp = vtotal.request("files", files=files, method="POST")
        # file_id = resp.data['id'].strip("==")
        # #file_id = hashlib.sha1((os.path.basename(filepath)).encode('utf-8')).hexdigest()
        # print(resp.json())
        # report = vtotal.request(f"files/{file_id}")
        # print(report.data)





if __name__ == '__main__':
    active_scanlink('https://groups.google.com/')
