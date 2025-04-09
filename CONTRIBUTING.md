# Guide de contribution

Merci de votre intérêt à contribuer au Memory Forensics Toolkit! Ce document fournit des instructions pour contribuer efficacement au projet.

## Comment contribuer

### 1. Signalement de bugs

Si vous trouvez un bug, veuillez créer un ticket dans l'onglet "Issues" de GitHub en incluant:

- Une description claire et concise du bug
- Les étapes pour reproduire le problème
- Le comportement attendu vs. le comportement observé
- Des captures d'écran si applicables
- Informations sur l'environnement (OS, version PowerShell, version Volatility)

### 2. Proposition de fonctionnalités

Pour suggérer de nouvelles fonctionnalités:

- Vérifiez d'abord que la fonctionnalité n'est pas déjà proposée dans les "Issues"
- Créez un nouveau ticket avec le label "enhancement"
- Décrivez en détail la fonctionnalité et pourquoi elle serait utile
- Si possible, proposez une implémentation

### 3. Contribution au code

1. **Fork le projet**
2. **Créez une branche de fonctionnalité**:
   ```
   git checkout -b feature/ma-nouvelle-fonctionnalite
   ```
3. **Assurez-vous de suivre les conventions de codage**:
   - Respectez le style PowerShell
   - Commentez votre code de manière appropriée
   - Ajoutez des tests si nécessaire
4. **Committez vos changements**:
   ```
   git commit -m 'Ajout d'une nouvelle fonctionnalité'
   ```
5. **Push vers votre branche**:
   ```
   git push origin feature/ma-nouvelle-fonctionnalite
   ```
6. **Ouvrez une Pull Request**

## Conventions de codage

### PowerShell

- Utilisez PascalCase pour les noms de fonctions et de variables
- Préfixez les fonctions par un verbe (Get-, Set-, Invoke-, etc.)
- Documentez les fonctions avec des commentaires descriptifs
- Utilisez des espaces, pas des tabulations
- Utilisez des accolades sur de nouvelles lignes

Exemple:
```powershell
function Invoke-MyFunction {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RequiredParameter,
        
        [Parameter(Mandatory = $false)]
        [int]$OptionalParameter = 0
    )
    
    # Description de ce que fait la fonction
    $result = $RequiredParameter + $OptionalParameter
    return $result
}
```

### Structure des modules

- Chaque module doit être dans son propre répertoire sous `/modules/`
- Chaque module doit avoir un fichier principal `analyzer.ps1`
- Les fonctions auxiliaires doivent être dans des fichiers séparés

## Tests

Avant de soumettre votre PR:

1. Testez votre code avec différents dumps mémoire si possible
2. Vérifiez les erreurs potentielles
3. Assurez-vous que la sortie est formatée correctement

## Révision de code

Toutes les Pull Requests seront examinées. La révision peut inclure:

- Vérification de fonctionnalité
- Vérification de style
- Test de performance
- Revue de sécurité

## Licence

En contribuant, vous acceptez que votre code soit distribué sous la même licence que le projet (MIT). 