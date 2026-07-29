# Revue de conformité des contrôles

Revue réalisée le 28 juillet 2026 à partir du référentiel public ANSSI et des
comportements Active Directory documentés par Microsoft.

## Principes appliqués

- Les RID sont extraits du SID lorsque la colonne ORADAD `rid` est absente.
- Les principaux Tier 0 et les groupes opératifs vides ne sont pas considérés
  comme points d'entrée d'un chemin d'attaque ACL.
- Les permissions natives nécessaires au fonctionnement d'AD sont tolérées de
  manière ciblée, notamment la réplication des RODC.
- `Replicating Directory Changes All` reste dangereux sur la partition du
  domaine pour les RODC.
- Les droits d'enrôlement ADCS ne sont pas confondus avec des droits permettant
  de modifier un modèle de certificat.
- Les propriétaires sont contrôlés uniquement sur les classes publiées par
  l'ANSSI, pour les objets âgés de plus de sept jours.
- Les contrôles multi-niveaux exposent séparément `Levels` et `FailedLevels`.
- Un certificat est vérifié pour DSA, ROCA, taille RSA, exposant RSA et
  algorithme de signature.

## Tests de non-régression

Le test de fumée impose :

- exactement 76 identifiants ANSSI uniques ;
- aucun contrôle non évalué ;
- l'égalité des niveaux avec le catalogue ;
- l'absence de faux positifs sur les ACL natives RODC, DC, DFSR, MicrosoftDNS,
  gMSA et modèles ADCS de l'extract de référence ;
- l'échec de `dSHeuristics` au seul seuil 4 lorsque les caractères de
  durcissement 28 et 29 ne sont pas explicitement positionnés à `1`.
