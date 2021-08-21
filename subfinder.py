import re
import sys
import requests
import itertools
from multiprocessing import Pool
from collections import OrderedDict


SOURCES = [
		"https://otx.alienvault.com/api/v1/indicators/domain/$/passive_dns",
		"https://jldc.me/anubis/subdomains/$",
		"https://dns.bufferover.run/dns?q=.$",
		"https://tls.bufferover.run/dns?q=.$",
		"https://api.certspotter.com/v1/issuances?domain=$&include_subdomains=true&expand=dns_names",
		"https://crt.sh/?q=%.$",
		"http://api.hackertarget.com/hostsearch/?q=$",
		"https://rapiddns.io/subdomain/$",
		"https://riddler.io/search?q=pld:$&view_type=data_table",
		"https://sonar.omnisint.io/subdomains/$?page=",
		"https://api.sublist3r.com/search.php?domain=$",
		"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$",
		"https://api.threatminer.org/v2/domain.php?q=$&rt=5"#,
		"http://web.archive.org/cdx/search/cdx?url=*.$/*&output=txt&fl=original&collapse=urlkey"
	  ]


def send_requests(data):
	domain = data[0]
	link   = data[1]

	#request data from
	try:
		response = requests.get(link, timeout=3)

	except requests.exceptions.Timeout as e:
		return []

	#get subdomains from response
	pattern = "[a-z0-9_.-]+\." + domain
	subdomains = re.findall(pattern, response.text)

	#remove duplicates
	return list(OrderedDict.fromkeys(subdomains))



def subfinder(domain):
	#update source list with domain
	sources = [[domain, source.replace("$", domain)] for source in SOURCES]

	#send requests
	p = Pool(processes=14)
	result = p.map(send_requests, sources)
	p.close()

	#combine lists and remove duplicates
	subdomains = list(set(itertools.chain.from_iterable(result)))
	return subdomains


#use command line
for subdomain in subfinder(sys.argv[1]): print(subdomain)
