# ADS-Open

ADS-Open est un moteur d'audit PowerShell indépendant qui exploite directement
les exports TSV d'ORADAD. Il exécute des contrôles publics de l'ANSSI, calcule un
niveau global de 1 à 5 et génère un rapport HTML et JSON.

> ADS-Open n'est pas le moteur ADS officiel et n'est ni produit, ni certifié,
> ni soutenu par l'ANSSI.

## Prérequis

- Windows PowerShell 5.1 ou PowerShell 7+
- aucun module Active Directory requis

## Utilisation

En amont, réaliser un export des données annuaire avec ORADAD. dans le fichier xml de l'ORADAD il faut mettre les valeur suivantes:

   \<outputFiles\>1\</outputFiles\>                        \<!-- Enable output cleartext files --\>
   
   \<outputMLA\>0\</outputMLA\>                            \<!-- Enable output encrypted MLA archive --\>
   

Ici, on exporte les données dans .\oradad-out

Ensuite on lance ADS-Open:

```powershell
.\ADS-Open.ps1 `
  -InputPath .\oradad-out `
  -OutputPath .\output `
  -Format Both
```

Le script localise automatiquement le dernier répertoire de collecte contenant
`tables.tsv`, reconstruit les en-têtes depuis le schéma ORADAD, puis produit :

- `output\report.html`
- `output\report.json`

## Scoring

Le niveau est le plus petit niveau ANSSI associé à un contrôle en échec. En
l'absence d'échec parmi les contrôles exécutés, le niveau est 5. Cette règle est
transparente et reproductible ; elle ne prétend pas reproduire les pondérations
internes non publiées du service ADS.

## Couverture des contrôles

À partir de la version 1.2.0, le rapport distingue trois catégories ANSSI :

- 76 vulnérabilités (`vuln_*`), seules susceptibles de produire un échec et
  d'influencer le niveau global ou les points cumulés ;
- 37 avertissements (`warning_*`), présentés sans effet sur la note ;
- 13 informations (`info_*`), également sans effet sur la note.

Depuis la version 1.3.0, chacune des 76 vulnérabilités comporte une section
dépliable **Description détaillée** reprenant sa portée ainsi que les
recommandations, annotations, limites et acceptations publiées par l'ANSSI.
La date de vérification du référentiel et un lien vers la fiche officielle sont
également affichés. À partir de la version 1.3.1, la restitution HTML est entièrement
autonome : les liens externes sont supprimés et le texte intégral embarqué est
structuré en paragraphes, sous-titres et encadrés pour une consultation hors ligne.

Pour chaque avertissement ou information, le rapport indique l'identifiant, le
titre, les niveaux indicatifs publiés et la date d'introduction lorsqu'elle
figure dans le changelog ANSSI. L'absence de date est explicitement signalée.

Chaque vulnérabilité reçoit obligatoirement l'un des états `Passed`, `Failed` ou
`NotEvaluated`. Un contrôle non implémenté ou non concluant faute de données
n'est jamais considéré comme validé et n'influence pas artificiellement le score.

La version actuelle évalue les contrôles directement depuis les TSV, notamment
les comptes privilégiés résolus récursivement, `adminCount`, Protected Users,
les silos d'authentification, les secrets des DC/serveurs/MSA, Kerberos,
SIDHistory, les délégations, `krbtgt`, MachineAccountQuota et NTFRS. Les
contrôles ACL s'appuient sur un moteur dédié de décodage des descripteurs et
de construction de chemins transitifs, décrit dans
[`docs/ACL-Engine.md`](docs/ACL-Engine.md).

Référentiel public : [Points de contrôle Active Directory de l'ANSSI](https://www.cert.ssi.gouv.fr/uploads/guide-ad.html).

## Données sensibles

Les exports ORADAD et les rapports générés contiennent des informations
sensibles sur l'annuaire audité. Ils ne doivent jamais être publiés. Les
répertoires usuels d'exports et de rapports sont exclus par `.gitignore`.

## Licence

Copyright © 2026 Pierre Faurant.

ADS-Open est distribué sous licence
[GNU General Public License version 3](LICENSE) (`GPL-3.0-only`).
