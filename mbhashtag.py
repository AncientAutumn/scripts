#Version 1 - Basic function

#Generate a list of hashes which based on the tags searched in malwarebazaar
#The maximum limit is 1000 hashes

import requests
import json

def apiCall(tag):
	headers = {'User-Agent' : 'Mozilla/5.0'}
	payload = {'query' : 'get_taginfo', 'tag' : tag, 'limit' : '1000'}
	url = "https://mb-api.abuse.ch/api/v1/"

	res = requests.post(url, data=payload, headers=headers)
	data = res.json()
	return data

print("What tag would you like to search the hash for?")
tag = input("> ")

print("Which format do you want it to be?")
print("[1] SHA1")
print("[2] SHA256")
print("[3] MD5")
hashformat = input("> ")


if hashformat == '1':
	data = apiCall(tag)
	for x in data['data']:
		print(str(x["sha1_hash"]))
elif hashformat == '2':
	data = apiCall(tag)
	for x in data['data']:
		print(str(x["sha256_hash"]))
elif hashformat == '3':
	data = apiCall(tag)	
	for x in data['data']:
		print(str(x["md5_hash"]))
else:
	print("Not a valid option")
