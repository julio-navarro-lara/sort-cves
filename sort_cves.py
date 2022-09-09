import sys
import requests
import pprint
import json
from random import randint
from time import sleep

def obtain_cve_details(cve_id):
    response = requests.get('https://services.nvd.nist.gov/rest/json/cve/1.0/'+cve_id+'?addOns=dictionaryCpes')
    return response.json()

def extract_cve_base_score(json_response):
    try:
        base_score = float(json_response["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
    except:
        base_score = -1.0
    return base_score

def extract_cve_cvssv3_string(json_response):
    try:
        cvssv3_string = json_response["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
    except:
        cvssv3_string = "N/A"
    return cvssv3_string 

def split_string_cve(str_cve):
    #We also remove duplicates
    result = list(set([s.strip() for s in str_cve.split(",")]))
    return result

def order_cve_dict(cve_dict):
    return dict(sorted(cve_dict.items(), reverse=True, key=lambda item: (item[1],item[0])))

def print_cve_dict(cve_dict):
    print(", ".join(list(cve_dict.keys())))

if __name__=="__main__":
    print("Ordering CVEs by CVSSv3 script - by dedalus")
    print("-------------------------------------------")
    if len(sys.argv) <= 1:
        print("Please provide a string of CVE ids as the first argument")
    else:
        list_cve = split_string_cve(sys.argv[1])
        cve_dict = {}
        for cve_id in list_cve:
            request_result = obtain_cve_details(cve_id)
            base_score = extract_cve_base_score(request_result)
            cvssv3_string = extract_cve_cvssv3_string(request_result)
            cve_dict[cve_id] = base_score
            if base_score < 0.0:
                print(cve_id+': N/A - '+cvssv3_string)
            else:
                print(cve_id+': '+str(base_score)+' - '+cvssv3_string)
            
            sleep(randint(3,10))
        
        print_cve_dict(order_cve_dict(cve_dict))
