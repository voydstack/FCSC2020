# Deterministic ECDSA - Crypto - 50

> On vous demande d'évaluer la sécurité d'un serveur de stockage de données en cours de développement.

Pour commencer les challs crypto, nous avons affaire à une implémentation assez hasardeuse de l'algorithme ECDSA permettant de signer des messages de façon sécurisée.

Le code source du serveur nous est donné.

## Analyse du fonctionnement de l'application

En se connectant au serveur distant, certaines informations nous sont données, notamment les caractéristiques publiques de la courbe elliptique:

```
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
=-= ECC-Based Secure Flag Storage =-=
=-=      (under development)      =-=
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Public Point Q:
  Q.x: 0x40276f768df2ee9c83d935f10036734ea50c235b2c5c48295e498776ec02c4b6
  Q.y: 0xd3e076127e072d8a5743828683a9d16ee12c9d8d3c6782a37c2fbda11fd77d81
```

Remarque: Pour l'anecdote, la courbe elliptique utilisée a été [publiée par l'ANSSI](https://www.legifrance.gouv.fr/affichTexte.do;jsessionid=?cidTexte=JORFTEXT000024668816&dateTexte=&oldAction=rechJO&categorieLien=id) et est utilisée notamment dans les services d'administration français.

Il nous est ensuite demandé de rentrer notre nom:

```
What is your name?
>>> voydstack
```

Une fois que nous l'avons rentré, différents tokens valides nous sont affichés (encodés en base64), puis il nous est demandé de fournir une signature valide pour l'utilisateur "admin" afin de récupérer le flag.

Nous devons donc trouver un moyen de déterminer le token admin.

## Analyse du code de l'application

Le code donné est le suivant:

```py
from fastecdsa.curve import Curve
from hashlib import sha256, sha512
from Crypto.Util.number import inverse as modinv
from base64 import b64encode as b64e, b64decode as b64d

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


def verify(C, Q, msg, r, s):

	if Q.IDENTITY_ELEMENT == Q:
		return False

	if not C.is_point_on_curve((Q.x, Q.y)):
		return False

	if r < 1 or r > C.q - 1:
		return False

	if s < 1 or s > C.q - 1:
		return False

	ctx = sha512()
	ctx.update(msg.encode())
	h = int(ctx.hexdigest(), 16)

	s_inv = modinv(s, C.q)
	u = h * s_inv % C.q
	v = r * s_inv % C.q
	P = u * C.G + v * Q
	return r == P.x

if __name__ == "__main__":

	sk = int(open("sk.txt", "r").read())

	C = Curve(
	    "ANSSIFRP256v1",
	    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03,
	    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00,
	    0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F,
	    0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1,
	    0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF,
	    0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB
	)

	print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
	print("=-= ECC-Based Secure Flag Storage =-=")
	print("=-=      (under development)      =-=")
	print("=-<=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")

	Q = sk * C.G
	print("Public Point Q:")
	print("  Q.x: 0x{:064x}".format(Q.x))
	print("  Q.y: 0x{:064x}".format(Q.y))

	print("What is your name?")
	while True:
		username = input(">>> ")
		if "|" not in username: break

	print("Here are a few user tokens:")
	for i in range(4):
		uid = "{}_#{:02x}".format(username, i)
		r, s = sign(C, sk, uid)
		token = b64e("{}|{}|{}".format(uid, r, s).encode()).decode()
		print(token)

	print("Access to flag is limited to admin user.")
	print("Enter admin token:")
	token = input(">>> ")
	token = b64d(token.encode()).decode().split('|')
	if token[0] != "admin":
		print("Error: access forbidden")
		exit(1)

	r, s = map(int, token[1:])
	if verify(C, Q, "admin", r, s):
		flag = open("flag.txt", "r").read()
		print("Here is the stored flag: {}".format(flag))
	else:
		print("Error: access forbidden")

```

Premièrement, nous remarquons que la clé privée **sk** est lue depuis un fichier présent sur le serveur, et n'est pas présente dans le code (ça aurait été trop facile !):

```py
sk = int(open("sk.txt", "r").read())
```

La clé publique est ensuite calculée depuis la clé privée et ses composantes nous sont affichées:
```py
Q = sk * C.G
	print("Public Point Q:")
	print("  Q.x: 0x{:064x}".format(Q.x))
	print("  Q.y: 0x{:064x}".format(Q.y))


```

Les tokens affichés sont en faite le résultat en base64 de la chaîne:

```username_#NN|r|s```

Avec:
* username: l'username que nous fournissons
* NN: Un nombre entier en hexadécimal sur 2 caractères
* r: La première composante de la signature de **username**
* s: La seconde composante de la signature de **username**

Pour arriver à obtenir le flag, nous devons donc avoir un token valide de la forme:

```admin|signature_r|signature_s```

Nous remarquons également 2 fonctions **sign** et **verify** qui vont respectivement signer un message donné et vérifier la signature associée.

[Selon Wikipedia](https://fr.wikipedia.org/wiki/Elliptic_curve_digital_signature_algorithm), l'algorithme pour la signature d'un message est le suivant:

* Choisir de manière aléatoire un nombre k entre 1 et n-1
* Calculer (i,j) = kG
* Calculer x = i mod n ; si x = 0, aller à la première étape
* Calculer y = k^(-1) (H(m) + sx) mod n où H(m) est le résultat d'un hachage cryptographique sur le message m à signer, souvent SHA-1 (le NIST et l'ANSSI conseillent de ne plus utiliser SHA-1 mais SHA-256 ou SHA-512, ethereum utilise Keccak-256, une variante de SHA-3).
* Si y = 0, aller à la première étape
* La signature est la paire (x, y).

Nous retrouvons donc plus ou moins cet algorithme dans la fonction **verify**, il y a cependant quelques particularités à noter.

* L'algorithme de hashage utilisé pour la fonction H(m) est SHA-512
* Le nonce k n'est pas aléatoire mais est simplement la valeur du hash SHA-256 du message

Le fait que ce nonce k soit non aléatoire est prédictible nous permet à l'aide d'une équation de retrouver la clé privée (ici sk) !

Nous pouvons retranscrire la formule du calcul de **y** avec les variables de l'application:

```s = k⁻¹ (SHA512(m) + sk * r) mod C.q```

## Exploitation de la vulnérabilitée

Grâce aux tokens donnés par l'application, nous connaissons ici:

* m
* r et s (signature du message m)
* n
* k (valeur de SHA256(m))

Par exemple pour le token suivant:

```voydstack_#00|44279756380352348230042587543091988998621213715331983324257173445675496016545|16579719699650216965727327221543519137664757563580780609311929611589323455839```

* m = "voydstack_#00"
* r = 44279756380352348230042587543091988998621213715331983324257173445675496016545
* s = 16579719699650216965727327221543519137664757563580780609311929611589323455839
* SHA512(m) = 0x9ef9a03b7fcbc2e571df9f88be9d7d82bdd0d0a12d88a549060fb6edb856ec30f97b6de36939b652a1fef18f0c93d900053fcfb99c2ebd7596dc15c1f278e7db
* k = SHA256(m) = 0x143ce298c28df10a46dffd96d326a192fc7e39cf80279d1c8899ee1ca538d90

À l'aide d'une petite équation, nous pouvons ainsi déterminer la clé privée **sk**:

```
sk = r⁻¹ * (s * k - SHA512(m)) mod C.q
```

Ce qui nous donne: 
```
sk = 78593266096774691231960415316042546555024606936601708022173287481629404126627
```

Super, nous avons tout ce qu'il nous faut pour fabriquer un token valide pour admin !
Faisons un petit script qui fera le travail à notre place !

```py
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
```

Ce qui nous donne: 
```
[+] Got private key sk = 78593266096774691231960415316042546555024606936601708022173287481629404126627
[*] Crafting admin token ...
[+] Got admin token: YWRtaW58ODI1NjM5Mzg3NzA1ODAxMzA2MDA3OTA3NzQ1MjQyMzM1Mjc5MDIwMjYwMzI2MDc1OTQyODQ3MjIwNjM5MDI2OTkwNjY5OTY4NTk2NDV8ODAwNjkyMDYzMjg5NDk1Mjk1MTg2MjA1NTg0MTQ4NzI5NDQ1Mjg1Mjk3NDQ5MTY1MTczNjAzMDk5MjQ1ODMwNDczNjg1ODkzNTI2MTQ=
[*] Getting your flag ...
[+] Here is the stored flag: FCSC{2d6d125887b96c90cc3e4243b5d2ed13e0f18caccf117cb923ebf3d1f327c036}
```

La signature est valide et nous pouvons obtenir le flag !

FLAG: FCSC{2d6d125887b96c90cc3e4243b5d2ed13e0f18caccf117cb923ebf3d1f327c036}

Remarque: Je débute en crypto, si vous voyez des choses incorrectes dans ce writeup n'hésitez pas à me le signaler! :)