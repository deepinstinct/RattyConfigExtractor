'''
Description:
Ratty config extractor is a python script that extracts the "command & control" server address from a Ratty malware

Usage:
pip install -r requirements.txt
python3 ratty-decrypt.py <path_to_ratty_jar_file>

Version:
0.1

Deep Instinct
'''

import zipfile
import base64
import sys
from art import *


if len (sys.argv) < 2:
	print("error: expected a ratty file as argument")
	print("usage: python3 ratty-decrypt.py /path/to/ratty") 
	sys.exit(0)

file = sys.argv[1]

print(text2art("Deep Instinct","tarty1"))

if zipfile.is_zipfile(file):
	with zipfile.ZipFile(file, mode="r") as archive:
		print("Trying to extract Command & Control server information from: "+file)
		try: #new versions
			config=archive.read('data')
			try: #new versions
				decoded = ''.join(chr(b ^ 56) for b in base64.b64decode(config))
				print(decoded)
			except: #for version 1.26.0 and maybe others
				decoded = ''.join(chr(b ^ 56) for b in config)
				print(decoded)
		except:
			try: #for version 1.20.1 and maybe others
				config=archive.read('connection_data')
				print(config)
			except:
				print("something went wrong, it seems there is no c2 data in the JAR")
				sys.exit(1)
else:
	print("File is not a valid archive")
