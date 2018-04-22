import argparse
import time
import requests
#Mimics urlscan to create a summary paragraph of the high level details
def create_paragraph(json):
	time.sleep(15)
	get = requests.get("https://urlscan.io/api/v1/result/"+json['uuid'])
	get = get.json()
	main_ip = get['page']['ip']
	location = get['page']['city'] + "," + get['page']['country']
	owner = get['page']['asnname']
	main_domain = get['page']['domain']
	transaction_count = len(get['data']['requests'])
	ip_count = len(get['stats']['ipStats'])
	domain_count = len(get['stats']['regDomainStats'])
	secure_requests = get['stats']['secureRequests']
	countries = get['stats']['uniqCountries']
	links = get['stats']['totalLinks']
	verified_malicious = get['stats']['malicious']
	ads = get['stats']['adBlocked']
	print "This website contacted " + str(ip_count) + " IPs in " + str(countries) + " countries across " + str(domain_count) + " domains to perform " + str(transaction_count) + " HTTP transactions. Of those, " + str(secure_requests) + " were HTTPS. The page contains " + str(links) + " links, " + str(verified_malicious) + " of which are verified malicious and " + str(ads) + " were links to ads." + " The main IP is " + str(main_ip) + " located in " + str(location) + " and belongs to " + str(owner) + ". The main domain is " + str(main_domain) + ". "

parser = argparse.ArgumentParser()
parser.add_argument("--url",help="first try")
args = parser.parse_args()


if args.url:
	headers = {'Content-Type': 'application/json','API-Key': 'API_KEY'}
	payload = "{\"url\": \"" + str(args.url) + "\", \"public\": \"on\"}"
	r = requests.post("https://urlscan.io/api/v1/scan/", data=payload,headers=headers)
	time.sleep(2)
	create_paragraph(r.json())