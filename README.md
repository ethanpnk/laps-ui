# LAPS-UI (PowerShell/WPF) — Client léger pour récupérer les mots de passe LAPS

> **Pourquoi ?**  
> Sous **Windows 11**, le petit client graphique « LAPS UI » historique n’est plus disponible officiellement.  
> Ce projet propose une **alternative légère, locale et open-source** pour consulter les mots de passe **Windows LAPS** (nouvelle génération) et **Legacy LAPS** directement depuis un poste client, **sans module ActiveDirectory**.

![Aperçu de l’application](docs/screenshot.png)

---

## 📦 Ce qui est fourni

- **Script PowerShell (.ps1)** : disponible **dans le dépôt** (`LAPS-UI.ps1`).
- **Binaire Windows (.exe)** : disponible **dans l’onglet _Releases_** de ce dépôt.

> ℹ️ Le binaire `.exe` fourni dans les releases **n’est pas signé** (pas de code-signing).  
> - Windows SmartScreen / certains EDR peuvent afficher un avertissement ou bloquer l’exécution.  
> - Utilisez idéalement le **.ps1** (signé par vos soins) ou signez le `.exe` avant de le déployer en production.  
> - Vérifiez toujours l’**empreinte SHA256** du fichier téléchargé (voir plus bas).

---

## ✨ Fonctionnalités

- 🔐 Lecture des attributs LAPS dans Active Directory via LDAP/LDAPS :
  - **Windows LAPS** : `msLAPS-Password` (+ expiration)
  - **Legacy LAPS** : `ms-Mcs-AdmPwd` (+ expiration)
- 🖥️ UI moderne **WPF thème sombre** (Windows 10/11, DPI friendly).
- 🔎 Recherche par **nom de PC** (CN / sAMAccountName / dNSHostName).
- 🌐 **LDAP** par défaut ou **LDAPS (TLS 636)** via une case à cocher.
- 👁️ **Afficher/Masquer** le mot de passe ; **Copier** avec **compte à rebours** (20 s) et purge automatique du presse-papiers.
- 🧠 Option **« Mémoriser l’utilisateur »** (stocke *uniquement* le nom d’utilisateur dans `%LOCALAPPDATA%\LAPS-UI\prefs.json`).
- ⚠️ **Aucune sauvegarde de mots de passe** sur disque. Pas de module AD requis.

---

## ✅ Prérequis

- **Windows 10/11**  
- **Windows PowerShell 5.1**  
- **.NET Framework 4.7+**  
- Accès réseau vers un **contrôleur de domaine** (LDAP 389 / LDAPS 636)  
- **Droits de lecture LAPS** sur les objets **Computer** ciblés (ACL/GPO Microsoft LAPS)

---

## 🔧 Installation & Lancement

### Option A — Script PowerShell (recommandée si SmartScreen/EDR strict)
1. Récupérez `LAPS-UI.ps1` depuis le dépôt.
2. (Optionnel) Débloquez le fichier si nécessaire :
   ```powershell
   Unblock-File .\LAPS-UI.ps1
3. Lancez en STA :
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -sta -File .\LAPS-UI.ps1

### Option B — Exécutable (.exe) depuis Releases

1. Téléchargez la version souhaitée depuis l’onglet Releases.
2. Vérifiez l’empreinte SHA256 (exemple) :
   ```powershell
   Get-FileHash .\LAPS-UI.exe -Algorithm SHA256 | Select-Object Hash
3. Exécutez LAPS-UI.exe.
Si SmartScreen/EDR bloque : utilisez le .ps1, signez le binaire, ou faites approuver le binaire par vos politiques (AppLocker/WDAC/EDR).

---

## 🚀 Utilisation

1. Utilisateur / Mot de passe : entrez un compte disposant des droits de lecture LAPS
(ou laissez vide pour tenter avec vos identifiants de session si votre ACL l’autorise).
2. Contrôleur/Domaine : renseignez votre DC/nom de domaine.
3. LDAPS : cochez si votre DC expose 636/TLS avec certificat valide (recommandé en prod).
4. Nom de l’ordinateur : saisissez le PC cible (ex. PC-IT-1234).
5. Cliquez Récupérer → affichage du type de LAPS, expiration, et (si autorisé) mot de passe.
6. Copier : le mot de passe est copié et un compte à rebours de 20 s purge automatiquement le presse-papiers.

---

## 🔒 Sécurité

- Aucun mot de passe n’est écrit sur disque.
- Le presse-papiers est purgé après 20 s (si son contenu est toujours le mot de passe copié).
- La copie tente d’utiliser l’API WinRT (option `IsAllowedInHistory=false`) pour éviter l’historique Win+V.
- Selon la configuration Windows/tenant, cette exclusion peut ne pas être honorée pour des apps non packagées.  
  **Solutions 100 % efficaces** : désactiver l’historique du presse-papiers via GPO, ou packager en **MSIX** signé.
- L’option « Mémoriser l’utilisateur » ne stocke que `UserName` et `RememberUser` dans `%LOCALAPPDATA%\LAPS-UI\prefs.json`.

---

## 🧩 Dépannage (FAQ rapide)

### Introuvable / pas d’attributs LAPS
- Vérifiez l’orthographe, l’OU, et vos droits de lecture LAPS.
- Essayez **CN**, **sAMAccountName** (`...$`) ou **dNSHostName**.

### LDAPS échoue
- Certificat serveur valide ? Port **636** ouvert ? **CN/SAN** du cert = nom du serveur ?
- Testez d’abord en **LDAP signé** (case LDAPS décochée), puis repassez en **LDAPS**.

### Le mot de passe apparaît dans Win+V
- Possible si Windows ignore `IsAllowedInHistory` hors **MSIX**.  
  → Désactiver l’historique via **GPO** ou packager en **MSIX** signé.

### SmartScreen/EDR bloque l’EXE
- Préférez le **PS1**, ou **signez** l’EXE et faites l’approuver via **AppLocker/WDAC/EDR**.

---

## 🧪 Compatibilité

- **Windows PowerShell 5.1**
- Non prévu pour **PowerShell 7** (WPF/WinRT différent)
