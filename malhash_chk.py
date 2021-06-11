import datetime
import re
import sys

import dns.resolver
import requests
from colorama import Fore, Style, init
from requests.structures import CaseInsensitiveDict

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.3"
__description__ = "Query hash against malware hash repos."

# Intialize colorama
init()


headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"}


def shadow_srv(hash_str):
    url = f"https://api.shadowserver.org/malware/info?sample={hash_str}"
    title = f"{Style.BRIGHT}ShadowServer{Style.RESET_ALL}"
    try:
        resp = requests.get(url, headers=headers).json()
    except Exception as e:
        print(e)
    else:
        if resp:
            print(f"\n{Fore.RED}[+]{Fore.RESET} {title}: Hash found")
            for data in resp:
                if not data["anti_virus"] and data["adobe_malware_classifier"]:
                    print(f"\t{'Classifier':10} : {data['adobe_malware_classifier']}")
                    print(f"\t{'MD5':10} : {data['md5']}")
                    print(f"\t{'First Seen':10} : {data['first_seen']}")
                    print(f"\t{'Last Seen':10} : {data['last_seen']}")
                    print(f"\t{'Type':10} : {data['type']}")
                for av in data["anti_virus"]:
                    try:
                        print(f'{av["vendor"]}: {av["signature"]}')
                        print(av["md5"])
                        print(av["timestamp"], "\n")
                    except KeyError:
                        continue
        else:
            print(f"\n{Fore.GREEN}[x]{Fore.RESET} {title}: Hash not found")


def malbazaar(hash_str):
    url = "https://mb-api.abuse.ch/api/v1/"
    title = f"{Style.BRIGHT}MalBazaar{Style.RESET_ALL}"
    data = {"query": "get_info", "hash": hash_str}
    try:
        resp = requests.post(url, data=data, headers=headers).json()
    except Exception as e:
        print(e)
    else:
        if resp["query_status"] == "hash_not_found":
            print(f"\n{Fore.GREEN}[x]{Fore.RESET} {title}: Hash not found")
        elif resp["query_status"] == "no_json":
            print(f"\n{Fore.YELLOW}[!]{Fore.RESET} {title}: Query Failed")
        else:
            print(f"\n{Fore.RED}[+]{Fore.RESET} {title}: Hash found")
            if resp["data"]:
                for data in resp["data"]:
                    for k, v in data.items():
                        if k == "vendor_intel":
                            continue
                        print(f"\t {k.title().replace('_', ' '):30}: {v}")


def threatfox(hash_str):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    title = f"{Style.BRIGHT}ThreatFox{Style.RESET_ALL}"
    data = {"query": "search_hash", "hash": hash_str}
    headers = CaseInsensitiveDict([("Accept", "application/json")])

    try:
        resp = requests.post(url, headers=headers, json=data).json()
    except Exception as e:
        print(e)
    else:
        if resp["query_status"] == "hash_not_found":
            print(f"\n{Fore.GREEN}[x]{Fore.RESET} {title}: Hash not found")
        elif resp["query_status"] != "ok":
            print(f"\n{Fore.YELLOW}[!]{Fore.RESET} {title}: {resp['data']}")
        else:
            print(f"\n{Fore.RED}[+]{Fore.RESET} {title}: Hash found")
            if resp["data"]:
                for data in resp["data"]:
                    for k, v in data.items():
                        print(f"\t {k.title().replace('_', ' '):30}: {v}")


def malshare(hash_str):
    url = "https://malshare.com/daily/malshare.current.all.txt"
    title = f"{Style.BRIGHT}Malshare{Style.RESET_ALL}"
    try:
        resp = requests.get(url, headers=headers)
    except Exception as e:
        print(e)
    else:
        if resp.status_code == 200:
            match = re.findall(hash_str, resp.text)
            if match:
                print(f"\n{Fore.RED}[+]{Fore.RESET} {title}: Hash found")
            else:
                print(f"\n{Fore.GREEN}[x]{Fore.RESET} {title}: Hash not found")


def mhr(hash_str):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    title = f"{Style.BRIGHT}Cymru{Style.RESET_ALL}"
    try:
        for rdata in resolver.resolve(f"{hash_str}.malware.hash.cymru.com", "TXT"):
            unix_time = rdata.to_text().replace('"', "").split()[0]
            detection = rdata.to_text().replace('"', "").split()[1]
            last_seen = datetime.datetime.fromtimestamp(int(unix_time)).strftime("%Y-%m-%d %H:%M:%S")
            if last_seen:
                print(f"\n{Fore.RED}[+]{Fore.RESET} {title}: Hash found")
                print(f"\t{'Last Seen':10}: {last_seen}")
                print(f"\t{'Detection by A/V':10}: {detection}%")
    except dns.exception.Timeout:
        print("Timeout error")
    except dns.name.LabelTooLong:
        print(f"\n{Fore.YELLOW}[-]{Fore.RESET} {title}: Use MD5 hash")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print(f"\n{Fore.GREEN}[x]{Fore.RESET} {title}: Hash not found")


def main():
    if len(sys.argv) > 1:
        hash_str = sys.argv[1]
    else:
        sys.exit("Usage: python malhash_chk.py <hash>")

    print(f"{Fore.MAGENTA}Querying...{Fore.RESET}")
    shadow_srv(hash_str)
    malbazaar(hash_str)
    threatfox(hash_str)
    malshare(hash_str)
    mhr(hash_str)


if __name__ == "__main__":
    banner = fr"""
        __  ___      ____  __           __       ________              __
       /  |/  /___ _/ / / / /___ ______/ /_     / ____/ /_  ___  _____/ /__
      / /|_/ / __ `/ / /_/ / __ `/ ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
     / /  / / /_/ / / __  / /_/ (__  ) / / /  / /___/ / / /  __/ /__/ ,<
    /_/  /_/\__,_/_/_/ /_/\__,_/____/_/ /_/   \____/_/ /_/\___/\___/_/|_|
                                                                {__version__}
    """

    print(f"{Fore.CYAN}{banner}{Fore.RESET}")
    main()
