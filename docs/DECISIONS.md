# Decisions techniques

Historique des décisions d'architecture et choix techniques.

---

## DEC-001 : Développement local avant cloud

**Date** : 2026-02-16
**Statut** : Adopté

**Contexte** : Le spec original prévoyait un déploiement cloud dès la semaine 1 (Lambda, Firestore, Cloud Run). Les comptes cloud ne sont pas encore créés et le niveau Python est débutant.

**Décision** : Commencer 100% local (JSON + FastAPI local) et migrer vers le cloud quand le code fonctionne.

**Raison** : Réduire la complexité initiale. Apprendre Python sur du code fonctionnel localement avant d'ajouter la complexité cloud (IAM, networking, billing).

**Conséquence** : L'interface `BaseStorage` permet de passer de `LocalStorage` (JSON) à `FirestoreStorage` sans changer le reste du code.

---

## DEC-002 : Un cloud à la fois (AWS d'abord)

**Date** : 2026-02-16
**Statut** : Adopté

**Contexte** : Le spec prévoit 3 scanners (AWS, Azure, GCP) implémentés en parallèle.

**Décision** : Commencer par AWS seul, puis ajouter Azure (Phase 6) et GCP (Phase 7).

**Raison** : Surcharge cognitive si on apprend 3 SDKs cloud en même temps. AWS est le plus documenté et le plus demandé sur le marché.

---

## DEC-003 : Micro-étapes progressives (12 phases)

**Date** : 2026-02-16
**Statut** : Adopté

**Contexte** : Le spec original prévoit 5 semaines / 35 jours.

**Décision** : Découper en 12 phases plus petites, chacune produisant un livrable fonctionnel et testable.

**Raison** : Chaque phase donne un résultat visible. Si le projet s'arrête à la Phase 4, on a quand même un scanner AWS fonctionnel.

---

## DEC-004 : 1 repo par lab (pas de monorepo)

**Date** : 2026-02-18
**Statut** : Adopté

**Contexte** : Hésitation entre un monorepo `cloudsec-lab` contenant les 4 labs et des repos séparés.

**Décision** : Un repo GitHub par lab sous l'organisation `cloudsec-lab` (ex: `cloudsec-lab/iamguardian`).

**Raison** : L'organisation GitHub EST le conteneur. Un monorepo `cloudsec-lab/cloudsec-lab` est redondant. Les repos séparés donnent une meilleure visibilité (README, badges, stats individuels) pour un portfolio.

---

## DEC-005 : Nommage sans numéros

**Date** : 2026-02-18
**Statut** : Adopté

**Contexte** : Les dossiers étaient nommés `lab-1-iamguardian`, `lab-2-docclassifier`, etc.

**Décision** : Noms sans numéros : `iamguardian`, `docclassifier`, `securibot`, `threatpulse`.

**Raison** : Plus professionnel (modules, pas exercices scolaires). Pas de trou visible si un lab est supprimé. L'ordre est dans la documentation, pas dans les noms.

---

## DEC-006 : Validation par enum dans les endpoints FastAPI

**Date** : 2026-02-18
**Statut** : Adopté

**Contexte** : Les filtres `cloud` et `severity` de l'endpoint `GET /findings` acceptaient des `str` libres. Une valeur invalide (ex: `cloud=alibaba`) retournait silencieusement une liste vide au lieu d'une erreur.

**Décision** : Utiliser les enums `Cloud` et `Severity` comme types de paramètres FastAPI.

**Raison** : FastAPI valide automatiquement les valeurs enum et retourne un 422 (Unprocessable Entity) avec un message clair si la valeur n'est pas dans la liste. La documentation Swagger affiche aussi les valeurs possibles.

**Conséquence** : Les comparaisons passent de `f.cloud.value == cloud` (string) à `f.cloud == cloud` (enum), ce qui est plus lisible et type-safe.

---

## Voies abandonnées

### Monorepo cloudsec-lab/cloudsec-lab

**Raison d'abandon** : Redondance de nommage (org = repo), visibilité réduite par lab, pas de bénéfice réel (très peu de code partagé entre les labs).

### Firestore dès le départ

**Raison d'abandon** : Nécessite un compte GCP configuré + billing. Le stockage JSON local suffit pour le développement et les tests. Migration prévue en Phase 9.
