#!/usr/bin/env python
import sys,subprocess
from find_gadget import *

def make_default(binary,nc="",port=""):
	buf = ""
	buf += "from pwn import *\n\n"
	buf += "e = ELF(\"{0}\")\n".format(binary)
	if linked(binary) == 'dynamic':
		buf += "libc = e.libc\n"
	buf += "p = process(e.path)\n"
	buf += "#p = remote(\"{0}\",{1})\n".format(nc,port)
	buf += "context.log_level = \'debug\'\n\n"
	return buf

def bit(binary):
	output = subprocess.check_output("file "+binary,shell=True)
	if '32-bit' in output:
		return '32'
	if '64-bit' in output:
		return '64'

def linked(binary):
	output = subprocess.check_output("file "+binary,shell=True)
	if 'dynamically linked' in output:
		return 'dynamic'
	if 'statically linked' in output:
		return 'static'

argc = len(sys.argv)
if argc == 3:
	path = sys.argv[1]
	binary = sys.argv[2]
	payload = make_default(binary)

elif argc == 5:
	path = sys.argv[1]
	binary = sys.argv[2]
	nc = sys.argv[3]
	port = sys.argv[4]
	payload = make_default(binary,nc,port)

else:
	print("Usage : ./dalex.py $(pwd) (name of binary) (nc addr) (port)")
	sys.exit()

gadget = find_gadget(binary,bit(binary),linked(binary))
for key in gadget:
	payload += key +" = "+gadget[key] + "\n"

f = open(path+"/ex.py","w")
f.write(payload)
f.close()

