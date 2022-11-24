#Please replace x-apikey with your virustotal API key

import requests
import json

def queryString():
	print("Enter the Hash: ")
	hash = input("> ")
	print()
	query(hash)

def queryList():
	print("Destination of the file: ")
	filePath = input("> ")
	print()
	f = open(filePath, "r")
	for x in f:
		query(x.rstrip())
	print("=================================END====================================")
	exit()

def query(hash):
	url = "https://www.virustotal.com/api/v3/search?"
	payload = {'query': hash}
	headers = {'x-apikey': '<YOUR API KEY>'}
	res = requests.get(url, params=payload, headers=headers)

	data = res.json()

	for x in data['data']:
		print("========================================================================")
		print("SHA1:   " + x['attributes']['sha1'])
		print("MD5:    " + x['attributes']['md5'])
		print("SHA256: " + x['attributes']['sha256'])
		print()

while(True):
	print("How would you like to convert?")
	print("[1] Query using Hash String (e.g 5ebacb20f62fae0dd610d874583d13fac5024309)")
	print("[2] Query using Hash List (e.g /path/to/textfile.txt)")
	print("[3] Quit")
	option = input("> ")
	print()

	if option == '1':
		queryString()
	elif option == '2':
		queryList()
	elif option == '3':
		exit()
	else:
		print("Please choose a valid option")
		

