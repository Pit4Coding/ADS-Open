# Moteur ACL et chemins de contrôle

Le moteur lit les `nTSecurityDescriptor` binaires présents dans les partitions
ORADAD et les décode avec `RawSecurityDescriptor`. Il ne dépend ni de RSAT ni
d'un accès en ligne à Active Directory.

## Résolution

- les SID sont reliés aux utilisateurs, ordinateurs, groupes et comptes de
  service collectés ;
- les GUID d'attributs sont résolus depuis `schema/attribute.tsv` ;
- les droits étendus sensibles connus sont nommés explicitement ;
- les ACE administratives attendues (`SYSTEM`, administrateurs du domaine et
  de l'entreprise, contrôleurs de domaine, etc.) sont exclues ;
- les refus explicites sont appliqués aux autorisations correspondantes.

## Relations dangereuses

Le graphe prend notamment en compte :

- propriétaire non administratif ;
- `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` ;
- création et suppression d'enfants ;
- écriture globale ou écriture d'attributs sensibles (`member`, SPN, RBCD,
  KeyCredentialLink, UAC, gPLink, délégation et gMSA) ;
- réinitialisation de mot de passe ;
- droits DCSync ;
- enrôlement et auto-enrôlement de certificats ;
- appartenance récursive aux groupes.

Une recherche en largeur construit ensuite les chemins transitifs vers les
objets Tier 0, avec une profondeur maximale de huit relations afin de borner
les ressources consommées.

## Contrôles alimentés

Le moteur alimente les contrôles publics relatifs aux conteneurs et modèles
AD CS, `adminSDHolder`, contrôleurs de domaine, DFSR/SYSVOL, clés DPAPI,
gMSA, racines de partitions, schéma, MicrosoftDNS, GPO applicables aux
comptes privilégiés, conteneurs privilégiés, propriétaires et lisibilité des
descripteurs des comptes privilégiés.

## Limites assumées

L'analyse est conservatrice : une relation potentiellement exploitable est
signalée pour qualification. Elle ne modélise pas encore les conditions
dynamiques dépendant d'un correctif installé sur chaque contrôleur, d'une
configuration système extérieure à l'annuaire ou d'une acceptation de risque.
Ces cas ne doivent pas être automatiquement reclassés comme conformes.
