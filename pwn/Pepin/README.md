# Pépin - PWN - 50

> Vous avez accès à une machine qui semble avoir un noyau Linux possédant un appel système #333 particulier.

Un petit chall kernel pour entamer les challenges pwn, quel plaisir! 

On a donc affaire à un appel syscall custom ayant l'id 333.

## Éxecution de l'appel système

Ni une ni deux, on code un petit programme en assembleur pour tenter de percer les mystères de ce mystérieux syscall

```nasm
bits 64
global _start

_start:
	mov rax, 333
	syscall

	xchg rax, rdi
	mov rax, 60
	syscall
```

On exit également avec le code de retour du syscall pour voir ce qu'il nous renvoie.

On l'assemble puis on l'envoie directement sur la machine distante

```bash
nasm -f elf64 pepin.asm -o pepin.o
ld pepin.o -o pepin
```

Et là, en l'exécutant ... bah rien.
Le code de retour est 0, pas grand chose d'intéressant à en tirer.

Peut être que le flag est dissimulé quelque part en mémoire ? ;)

## Récupération du flag

On tente d'afficher la mémoire tampon du noyau avec ```dmesg```
Et là surprise, ce bon vieux flag était planqué là dedans !

FLAG: FCSC{b820fd6ce2365286396c923b899477577b0b97036a37ace0e93fd6b628d833ad}