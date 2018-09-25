import subprocess

def find_gadget(binary,bit,link):
	gadget = {}
	if bit == '64' and link == 'dynamic':
		try:
			prdi = subprocess.check_output("rp-lin-x64 -f "+binary+" -r 4 | grep 'pop rdi ; ret'",shell=True)
			prdi = int(prdi[prdi.find("0x"):19],16)
			gadget['prdi'] = hex(prdi)
			prsir15 = subprocess.check_output("rp-lin-x64 -f "+binary+" -r 4 | grep 'pop rsi ; pop r15 ; ret'",shell=True)
			prsir15 = int(prsir15[prsir15.find("0x"):19],16)
			gadget['prsir15'] = hex(prsir15)
			prdx = subprocess.check_output("rp-lin-x64 -f "+binary+" -r 4 | grep 'pop rdx ; ret'",shell=True)
			prdx = int(prdx[prdx.find("0x"):19],16)
			gadget['prdx'] = hex(prdx)
		except:
			pass

	return gadget

	
