# Memory Forensics Toolkit

Une boîte à outils complète de forensique mémoire basée sur PowerShell utilisant Volatility 3.

![Memory Forensics](https://img.shields.io/badge/Memory-Forensics-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Volatility](https://img.shields.io/badge/Volatility-3.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Vue d'ensemble

Ce toolkit fournit un framework modulaire et organisé pour l'analyse de dumps mémoire avec Volatility 3. Il automatise les tâches forensiques courantes, identifie les activités suspectes et génère des rapports lisibles dans plusieurs formats.

## Prérequis

- PowerShell 5.1 ou supérieur
- Volatility 3 (installé et disponible dans le PATH)
- Un fichier dump mémoire d'un système Windows

## Installation

1. Cloner ce dépôt:
   ```
   git clone https://github.com/username/memory-forensics-toolkit.git
   cd memory-forensics-toolkit
   ```

2. Vérifier que Volatility 3 est correctement installé:
   ```
   vol --help
   ```

## Utilisation

Exécuter le script principal et fournir le chemin vers le fichier dump mémoire:

```powershell
.\forensics_toolkit\main.ps1 C:\path\to\memory.raw
```

Vous pouvez également fournir le chemin vers le dump mémoire lorsque vous y êtes invité.

### Menu d'analyse

Le toolkit propose un menu interactif avec plusieurs options:

1. Informations système
2. Analyse des processus
3. DLLs et modules
4. Analyse des handles
5. Analyse mémoire/malware
6. Analyse réseau
7. Analyse de fichiers
8. Analyse du registre
9. Activité utilisateur
10. Exécuter l'analyse complète
11. Quitter

## Fonctionnalités

Le toolkit inclut des modules d'analyse pour:

### 1. Informations système
- Détails de base du système à partir du dump mémoire

### 2. Analyse des processus
- Liste des processus et leurs relations
- Arguments de ligne de commande
- Historique de la console
- Détection de processus suspects

### 3. Analyse des DLLs et modules
- DLLs chargées par processus
- Modules kernel
- Objets driver
- Détection de modules suspects

### 4. Analyse mémoire
- Détection de malware (malfind)
- Injections mémoire
- Hooks API

### 5. Analyse réseau
- Connexions actives/récentes
- Détection de connexions suspectes

### 6. Analyse de fichiers
- Fichiers en mémoire
- Détection de fichiers suspects

### 7. Analyse du registre
- Clés d'exécution automatique
- Mécanismes de persistance
- Artefacts d'activité utilisateur

### 8. Analyse des handles
- Handles de processus vers fichiers, registre, etc.
- Détection de handles suspects

### 9. Analyse d'activité utilisateur
- Contenu du presse-papiers
- Historique des commandes de console
- Timeline d'exécution de programmes

## Structure du projet

```
forensics_toolkit/
├── core/                  # Fonctions principales du toolkit
│   ├── config.ps1         # Gestion de configuration
│   ├── utils.ps1          # Utilitaires généraux
│   └── report.ps1         # Génération de rapports
├── modules/               # Modules d'analyse spécialisés
│   ├── filesystem/        # Analyse de fichiers
│   ├── handles/           # Analyse de handles
│   ├── memory/            # Détection de malware
│   ├── modules/           # Analyse de DLLs et modules
│   ├── network/           # Analyse de connexions réseau
│   ├── processes/         # Analyse de processus
│   ├── registry/          # Analyse du registre
│   ├── system_info/       # Informations système
│   └── user_activity/     # Activité utilisateur
├── output/                # Dossier de sortie (rapports)
└── main.ps1               # Script principal
```

## Sorties

Le toolkit génère plusieurs types de sorties:

- Rapports texte pour chaque module d'analyse
- Fichiers CSV pour faciliter l'analyse des données
- Rapports HTML avec résultats formatés
- Timeline complète de l'activité suspecte

Toutes les sorties sont sauvegardées dans le répertoire `output`, organisées par horodatage et catégorie d'analyse.

## Personnalisation

Le toolkit est conçu avec la modularité à l'esprit. Vous pouvez facilement:

- Ajouter de nouveaux plugins Volatility
- Personnaliser la détection de patterns suspects
- Modifier les formats de rapport
- Ajouter de nouveaux modules d'analyse

## Limitations connues

- Le toolkit est conçu pour les dumps mémoire Windows
- Les performances peuvent varier en fonction de la taille du dump mémoire
- Certaines détections de patterns peuvent nécessiter des ajustements en fonction des formats de sortie spécifiques de Volatility 3
- Certains plugins peuvent ne pas fonctionner avec toutes les versions du système d'exploitation

## Dépannage

### Erreurs d'encodage
Si vous rencontrez des erreurs d'encodage avec des caractères Unicode, le toolkit utilise une méthode spéciale pour le plugin `windows.psscan` qui force l'encodage UTF-8.

### Plugins non supportés
Certains plugins peuvent ne pas être supportés selon votre version de Volatility. Le toolkit gère gracieusement ces situations en ignorant les plugins non supportés.

## Contribution

Les contributions sont les bienvenues! Veuillez suivre ces étapes:

1. Fork le projet
2. Créer une branche de fonctionnalité (`git checkout -b feature/amazing-feature`)
3. Commit vos modifications (`git commit -m 'Add some amazing feature'`)
4. Push vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.
