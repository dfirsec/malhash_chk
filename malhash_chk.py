
import datetime
import json
import random
import re
import sys

import colorama
import dns.resolver
import requests
from colorama import Back, Fore, Style

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.1"
__description__ = "Query hash against malware hash repos."

colorama.init()


user_agent_list = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    # Firefox
    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
]

headers = {'User-Agent': random.choice(user_agent_list)}


def malbazaar(hash_str):
    url = 'https://mb-api.abuse.ch/api/v1/'
    malb_txt = f"{Style.BRIGHT}MalBazaar{Style.RESET_ALL}"
    data = {
        'query': 'get_info',
        'hash': hash_str
    }
    try:
        resp = requests.post(url, data=data, headers=headers).json()
        if resp['query_status'] == 'hash_not_found':
            print(f"{Fore.GREEN}[x]{Fore.RESET} {malb_txt}: Hash not found")
        else:
            print(f"{Fore.RED}[+]{Fore.RESET} {malb_txt}: Hash found")
            if resp['data']:
                for v in resp['data']:
                    for k, i in v.items():
                        print(f" {k.title().replace('_', ' '):30}: {i}")

    except Exception as e:
        print(e)


def malshare(hash_str):
    url = 'https://malshare.com/daily/malshare.current.all.txt'
    mals_txt = f"{Style.BRIGHT}Malshare{Style.RESET_ALL}"
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            match = re.findall(hash_str, resp.text)
            if match:
                print(f"{Fore.RED}[+]{Fore.RESET} {mals_txt}: Hash found") #nopep8
            else:
                print(f"{Fore.GREEN}[x]{Fore.RESET} {mals_txt}: Hash not found") #nopep8
    except Exception as e:
        print(e)


def mhr(hash_str):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    mhr_txt = f"{Style.BRIGHT}MHR{Style.RESET_ALL}"
    try:

        for rdata in resolver.resolve(f'{hash_str}.malware.hash.cymru.com', 'TXT'):
            unix_time = rdata.to_text().replace('"', '').split()[0]
            detection = rdata.to_text().replace('"', '').split()[1]
            last_seen = datetime.datetime.fromtimestamp(
                int(unix_time)).strftime('%Y-%m-%d %H:%M:%S')
            if last_seen:
                print(f"{Fore.RED}[+]{Fore.RESET} {mhr_txt}: Hash found")  # nopep8
                print(f"{'Last Seen':17}: {last_seen}\n{'Detection by A/V':17}: {detection}%")  # nopep8
    except dns.exception.Timeout:
        print("Timeout error")
    except dns.name.LabelTooLong:
        print(f"{Fore.YELLOW}[-]{Fore.RESET} {mhr_txt}: Use MD5 hash")  # nopep8
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.GREEN}[x]{Fore.RESET} {mhr_txt}: Hash not found")  # nopep8


def main():
    if len(sys.argv) > 1:
        hash_str = sys.argv[1]
    else:
        sys.exit("Usage: python malhash_chk.py <hash>")

    print(f"{Fore.YELLOW}Querying...{Fore.RESET}")
    malbazaar(hash_str)
    malshare(hash_str)
    mhr(hash_str)


if __name__ == "__main__":
    banner = fr'''
        __  ___      ____  __           __       ________              __
       /  |/  /___ _/ / / / /___ ______/ /_     / ____/ /_  ___  _____/ /__
      / /|_/ / __ `/ / /_/ / __ `/ ___/ __ \   / /   / __ \/ _ \/ ___/ //_/
     / /  / / /_/ / / __  / /_/ (__  ) / / /  / /___/ / / /  __/ /__/ ,<
    /_/  /_/\__,_/_/_/ /_/\__,_/____/_/ /_/   \____/_/ /_/\___/\___/_/|_|
    '''

    print(f"{Fore.CYAN}{banner}{Fore.RESET}")
    main()
