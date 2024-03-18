import sys
import nvdlib
import time
import random

def get_cve_details(cve_id):
    # Add a random delay between 1 and 5 seconds to prevent API blocking
    time.sleep(random.randint(1, 5))

    # Search for the CVE in NVD
    results = nvdlib.searchCVE(cveId=cve_id)
    # print(results)
    if not results:
        return None, None, None
    cve = results[0]

    # Use CVSSv3 score, and if not available, use CVSSv2
    if "v31score" in cve:
        score = cve.v31score
        cvss_string = cve.v31vector
        score_type = "CVSSv3"
    else:
        score = cve.v2score
        cvss_string = cve.v2vector
        score_type = "CVSSv2"
    #score = cve.v31score if cve.v31score is not None else cve.v20score
    #score_type = "CVSSv3" if cve.v31score is not None else "CVSSv2"
    #cvss_string = cve.v31vector if cve.v31score is not None else cve.v20vector

    return score, score_type, cvss_string

def main(cve_list):
    detailed_scores = {}

    # Get details for each CVE and print them
    for cve in cve_list:
        score, score_type, cvss_string = get_cve_details(cve)
        if score is not None:
            detailed_scores[cve] = (score, score_type, cvss_string)
            print(f"{cve} - {cvss_string} - {score}")

    # Sort CVEs by score in descending order
    sorted_cves = sorted(detailed_scores.items(), key=lambda x: x[1][0], reverse=True)

    # Print sorted CVEs with details
    print("\nSorted CVEs with Details:")
    for cve, score_info in sorted_cves:
        print(f"{cve} - {score_info[2]} - {score_info[0]}")

    # Print sorted CVEs codes only
    sorted_cves_codes = [cve for cve, _ in sorted_cves]
    print("\nSorted CVE Codes:", ", ".join(sorted_cves_codes))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide a list of CVEs separated by commas.")
        sys.exit(1)

    # Split the input string into a list, assuming CVEs are separated by ", "
    cve_input = sys.argv[1]
    cves = [cve.strip() for cve in cve_input.split(',')]
    main(cves)
