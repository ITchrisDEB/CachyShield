# Cachy Shield (français)

Centre de sécurité convivial pour Arch Linux et les distributions dérivées : **Analyser → Examiner → Corriger**, dans une
seule fenêtre, avec une confirmation avant chaque modification. Projet indépendant, non officiel (pas de lien avec CachyOS).

Voir le [README principal](README.md) (en anglais) pour les captures d'écran et le détail. En bref :

* **Installation** : `./install.sh` vérifie les dépendances, propose d'installer celles qui manquent (`sudo pacman -S --needed`,
  toujours après votre accord), compile, installe dans `/usr/bin` (à lancer avec `sudo ./install.sh` ; le mot de passe administrateur n'est demandé qu'**une
  fois**), ajoute le lanceur, l'icône et l'icône de la zone de notification au démarrage de session.
  `./install.sh --no-autostart` pour ne pas démarrer l'icône, `sudo cachy-shield-uninstall` (depuis n'importe quel dossier, le dossier cloné peut être supprimé) pour tout retirer.
* **Outils utilisés** : arch-audit, Lynis, rkhunter, Trivy, OSV-Scanner (recommandés), plus snapper, ufw ou firewalld, paru ou yay
  (facultatifs). Aucune dépendance à `cachy-update`.
* **Sécurité** : rien n'est modifié sans votre clic ; le pare-feu n'est jamais activé automatiquement ; l'AUR n'est jamais
  installé sans relecture du PKGBUILD ; vos environnements virtuels ne sont jamais touchés.
* **Vie privée** : aucune télémétrie, aucun compte. L'application interroge seulement les bases de failles publiques
  (CISA KEV, NVD, Arch, Trivy, OSV) ; les mises à jour automatiques se désactivent.
* **Langues** : français, anglais, allemand, espagnol, italien, néerlandais ; suit la langue du système, modifiable dans
  l'application (en bas à gauche de la fenêtre).
