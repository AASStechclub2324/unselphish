import virustotal_python
from printv import printv
import os
from base64 import urlsafe_b64encode
import requests

api_key = "05a005915e6bd5d067fa6d4c6c985746a5c2b7d371b840500c2b0630f11c7b1c"

def active_scanlink(url):
    with virustotal_python.Virustotal(api_key) as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            
            # Safe encode URL in base64 format
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

            report = vtotal.request(f"urls/{url_id}")
            total_votes = str(report.data['attributes']['total_votes'])
            last_analysis_stats = str(report.data['attributes']['last_analysis_stats'])
        except virustotal_python.VirustotalError as err:
            print(f"Failed to send URL: {url} for analysis and get the report: {err}")
            return 'err', 'err'
    return total_votes, last_analysis_stats

def active_scandomain(url):
    with virustotal_python.Virustotal(api_key) as vtotal:
        resp = vtotal.request(f"domains/{url}")
        printv(resp.data)

def active_scanfile(filepath):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': api_key}

    files = {"file": (os.path.basename(filepath), open(os.path.abspath(filepath), "rb"))}

    resp = requests.post(url, files=files, params=params)
    with virustotal_python.Virustotal(api_key) as vtotal:
        file_id = resp.json()['sha1']
        report = vtotal.request(f"files/{file_id}")
        f_type = report.data['attributes']['type_description']
        last_analysis_stats = report.data['attributes']['last_analysis_stats']
        size = report.data['attributes']['size']
        name = report.data['attributes']['names'][0]
        total_votes = report.data['attributes']['total_votes']
        return f_type, last_analysis_stats, total_votes, name, size




if __name__ == '__main__':
    print(active_scanlink('https://groups.google.com/'))
    print(active_scanfile(r"C:\Users\Anutosh\Desktop\tree-736885_960_720.jpg"))