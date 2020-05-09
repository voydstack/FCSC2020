#!/usr/bin/python3

from fastecdsa.curve import Curve
from hashlib import sha256, sha512
from Crypto.Util.number import inverse as modinv
from base64 import b64encode as b64e, b64decode as b64d
from pwn import *

def sign(C, sk, msg):
	ctx = sha256()
	ctx.update(msg.encode())
	k = int(ctx.hexdigest(), 16)

	ctx = sha512()
	ctx.update(msg.encode())
	h = int(ctx.hexdigest(), 16)

	P = k * C.G
	r = P.x
	assert r > 0, "Error: cannot sign this message."

	s = (modinv(k, C.q) * (h + sk * r)) % C.q
	assert s > 0, "Error: cannot sign this message."

	return (r, s)

def getprivatekey(m, r, s):
	ctx = sha256()
	ctx.update(m.encode())
	k = int(ctx.hexdigest(), 16)

	ctx = sha512()
	ctx.update(m.encode())
	h = int(ctx.hexdigest(), 16)

	rinv = modinv(r, C.q)
	sk = (rinv * (s * k - h)) % C.q

	return sk

C = Curve(
    "ANSSIFRP256v1",
    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03,
    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00,
    0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F,
    0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1,
    0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF,
    0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB
)

if __name__ == '__main__':
	app = remote('challenges1.france-cybersecurity-challenge.fr', 2000)
	app.recvuntil('>>> ')
	app.sendline('voydstack')
	res = app.recvuntil('>>> ')

	token_parts = b64d(res.splitlines()[1]).decode().split('|')

	m = token_parts[0]
	r = int(token_parts[1])
	s = int(token_parts[2])

	sk = getprivatekey(m, r, s)

	log.success('Got private key sk = %d' % sk)

	log.info('Crafting admin token ...')

	admin_signature = sign(C, sk, "admin")
	token = b64e(("admin|%d|%d" % admin_signature).encode())

	log.success('Got admin token: %s' % token)

	app.sendline(token)

	log.info('Getting your flag ...')

	log.success(app.recv().decode().strip())
