#Version 1.0 - Basic function with output formatting

#Using malwarebazaar to check which hash in the list exist in the database
#It can also be used to check the other hash format i.e SHA1, SHA256 or MD5


import argparse
import requests
import json
import csv
import sys


def APICALL(hash):
	try:
		headers = {'User-Agent' : 'Mozilla/5.0'}
		payload = {'query' : 'get_info', 'hash' : x.rstrip()}
		url = "https://mb-api.abuse.ch/api/v1/"

		res = requests.post(url, data=payload, headers=headers)
		data = res.json()
		return data
	except KeyboardInterrupt:
		print("Process Ended")
		sys.exit()
	except Exception:
		pass
		
		
def otherHashFormat(data,c):
	if data['query_status'] == 'ok':
		sha1 = data['data'][0]['sha1_hash']
		sha256 =data['data'][0]['sha256_hash']
		md5 = data['data'][0]['md5_hash']
		row = [sha1, sha256, md5]
		print("Signature: " + str(data['data'][0]['signature']))
		print("SHA1     : " + str(sha1))
		print("SHA256   : " +str(sha256))
		print("MD5      : " +str(md5))
		print()
		writer = csv.writer(c)
		writer.writerow(row)
		

def checkValidHash(data, hash, c):
	try:
		if data['query_status'] == 'ok':
			print(hash, " \33[7;37;32m FOUND \33[0;0m")
			writer = csv.writer(c)
			writer.writerow([hash])
		else:
			print(hash, " \33[7;37;31m NOT FOUND \33[0;0m")
	except KeyboardInterrupt:
		print("Process Ended")
		sys.exit()
	except Exception:
		pass

try:
	arg_desc = ''''Using malware bazaar to check the list of hashes in their existing database.
	You can use this to...
	[1] Find if the list of IOC hashes exist in their database.
	[2] Convert SHA1, SHA256 and MD5 hashes and output as csv file.
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument("-o", "--output", required=True, help = "output file name (\33[7;37;31mrequired\33[0;0m)")
	parser.add_argument("-i", "--input", required=True, help = "path to input file (\33[7;37;31mrequired\33[0;0m)")
	args = parser.parse_args()

	filePath = args.input


	print("What would you like to do?")
	print("[1] Check for malicious hash in the list")
	print("[2] Get the other hash format of the malicious hash in the list")
	option = input("> ")
	print()

	if option == '1':
		f = open(filePath, "r")
		c = open(args.output, "w")
		
		for x in f:
			data = APICALL(x)
			checkValidHash(data, x.rstrip(), c)
		
	elif option == '2':
		f = open(filePath, "r")
		c = open(args.output, "w")
		header = ['SHA1 Hash', 'SHA256 Hash', 'MD5 Hash']
		writer = csv.writer(c)
		writer.writerow(header)
		
		for x in f:
			data = APICALL(x)
			otherHashFormat(data,c)

			
	f.close()
	c.close()
except KeyboardInterrupt:
	print("Process Ended")
	sys.exit()


