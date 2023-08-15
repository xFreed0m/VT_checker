import requests
import time
import argparse
import json

API_URL = "https://www.virustotal.com/api/v3/files/"
API_KEY = ""


def get_verdict(API_KEY, API_URL, ID, verbose_mode):
    params = {"accept": "application/json","x-apikey": API_KEY}
    time.sleep(15)
    response = requests.get(API_URL+ID, headers=params)
    data = response.json()

    if response.status_code == 200:
        if verbose_mode:
            with open("verbose_log.txt", "a") as log:
                log.write(json.dumps(data, indent=4) + "\n\n")
        if 'MALWARE' or 'GREYWARE' or 'RANSOM' or 'PHISHING' or 'BANKER' or 'ADWARE' or 'EXPLOIT' or 'EVADER' or 'RAT' or 'TROJAN' or 'SPREADER' in str(data['data']['attributes']['sandbox_verdicts']):
            print(f"[!!!] {ID} - Looks dirty.")
            return "Dirty"        
        else:
            print(f"[+] {ID} - seems clean.")
            return "Clean"

    else:
        print(f"{ID} - Not Found.")
        return "Not Found"


def main(input_file, free_mode, verbose_mode):
    dirty_counter = 0
    total_counter = 0  
    notfound_counter = 0

    with open(input_file, "r") as file:
        hashes = [line.strip() for line in file]

    output_file = "verdicts.txt"
    with open(output_file, "a") as outfile:
        for ID in hashes:
            if free_mode:
                print("[*]Free API mode activated, will wait 15 secondes between each request to maintain VirusTotal limits")
                verdict = get_verdict(API_KEY, API_URL, str(ID), verbose_mode)
                if verdict == "Dirty":
                    dirty_counter += 1
                    total_counter += 1
                elif verdict == "Clean":
                    total_counter += 1
                elif verdict == "Not Found":
                    notfound_counter += 1
                    total_counter += 1

                outfile.write(ID + verdict + "\n")
            else:
                verdict = get_verdict(API_KEY, API_URL, ID, verbose_mode)

        print("[=] Out of total of " + str(total_counter) + " hashes submmited " + str(dirty_counter) + " are DIRTY, " + str(notfound_counter) + " weren't found and " + str(total_counter-dirty_counter-notfound_counter) + " are clean.")

        print(f"[*] Total of {dirty_counter} hashes are dirty out of {total_counter} replies")


            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send file hashes to VirusTotal API and get the verdict.")
    parser.add_argument("input_file", type=str, help="Input file containing hashes.")
    parser.add_argument("--free", action="store_true", help="Limit to 4 requests per minute.")
    parser.add_argument("--verbose", action="store_true", help="Save response in logfile.")

    args = parser.parse_args()
    main(args.input_file, args.free, args.verbose)
