
import requests
import urllib3

# Suppress HTTPS insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
MISP_URL = 'https://113.11.117.92:8081'
API_KEY = 'peUBlSbd2Cx4YsW18DFJXwNuBSX6nbuusgpLZeas'
VERIFY_SSL = False

# List of IPs to scan
ip_list = ['61.160.194.160', '8.8.8.8', '123.123.123.123']

# Headers
headers = {
	'Authorization': API_KEY,
	'Accept': 'application/json',
	'Content-Type': 'application/json',
}

for ip in ip_list:
	print(f"\n🔍 Checking IP: {ip}")
	
	payload = {
		"returnFormat": "json",
		"type": ["ip-src", "ip-dst", "ip-src|ip-dst"],
		"value": ip
	}

	response = requests.post(f"{MISP_URL}/attributes/restSearch", headers=headers, json=payload, verify=VERIFY_SSL)
	
	if response.status_code == 200:
		data = response.json()
		if data.get('response', {}).get('Attribute'):
			print(f"⚠️  Found! IP {ip} is present in MISP.")
			for attr in data['response']['Attribute']:
				print(f"   - Event ID: {attr['event_id']} | Type: {attr['type']} | Category: {attr['category']}")
		else:
			print(f"✅ No matches found. IP not known to be malicious.")
	else:
		print(f"❌ Error querying MISP: {response.status_code} - {response.text}")
