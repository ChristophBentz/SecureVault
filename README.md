# Secure Vault – Alle Vorgänge in einer Datei

Dieses Repository enthält eine vollständig integrierte Anwendung, die alle Funktionen – von der Passwortverwaltung über Notizen und Kreditkartenverwaltung bis hin zu Sicherheitsfeatures wie Zwei-Faktor-Authentifizierung, automatischer Sperrung und Backups – in einer einzigen Python-Datei zusammenfasst. Die Anwendung wurde mit PyQt6 als GUI-Framework entwickelt und verwendet moderne Kryptografie-Methoden, um alle sensiblen Daten zu schützen.

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Hauptfunktionen und Abläufe](#hauptfunktionen-und-abläufe)
  - [Ressourcen- und Datenverzeichnis](#ressourcen--und-datenverzeichnis)
  - [Benutzeroberfläche und Widgets](#benutzeroberfläche-und-widgets)
  - [Passwortverwaltung](#passwortverwaltung)
  - [Notizenverwaltung](#notizenverwaltung)
  - [Kredit-/Debitkartenverwaltung](#kreditdebitkartenverwaltung)
  - [Zwei-Faktor-Authentifizierung (2FA)](#zwei-faktor-authentifizierung-2fa)
  - [Automatische Sperrung](#automatische-sperrung)
  - [Backup und Wiederherstellung](#backup-und-wiederherstellung)
- [Installation und Nutzung](#installation-und-nutzung)
- [Beitragende](#beitragende)
- [Lizenz](#lizenz)

## Überblick

**Secure Vault** ist ein multifunktionaler, sicherheitsfokussierter Passwortmanager. Die Anwendung bietet:

- **Passwortverwaltung:** Erstellen, Anzeigen, Bearbeiten und Löschen von Passwort-Einträgen.
- **Notizenverwaltung:** Sicheres Speichern und Verwalten persönlicher Notizen.
- **Kartenverwaltung:** Verwalten von Kredit- und Debitkartendaten inklusive einer ansprechenden Darstellung.
- **Datenverschlüsselung:** Alle sensiblen Daten werden mit Fernet (unter Verwendung von PBKDF2HMAC zur Schlüsselableitung) verschlüsselt.
- **Zwei-Faktor-Authentifizierung:** Optionale 2FA mit TOTP (via PyOTP) und QR-Code-Generierung.
- **Automatische Sperrung:** Die Anwendung sperrt sich nach einer festgelegten Inaktivitätszeit automatisch.
- **Backup & Wiederherstellung:** Möglichkeit, alle Daten als verschlüsseltes Backup zu exportieren und wiederherzustellen.
- **Theming:** Unterstützung von Dark- und Light-Themes für eine individuelle Benutzeroberfläche.

## Hauptfunktionen und Abläufe

Alle Vorgänge sind in einer einzigen Python-Datei integriert. Im Folgenden werden die wesentlichen Prozesse erläutert:

### Ressourcen- und Datenverzeichnis

- **Ressourcenpfad:**  
  Die Funktion `resource_path(relative_path)` sorgt dafür, dass alle benötigten Ressourcen (z. B. Themes, Icons) auch nach der Kompilierung mit PyInstaller gefunden werden.
- **Datenverzeichnis:**  
  Mithilfe von `appdirs.user_data_dir` wird ein plattformübergreifendes Verzeichnis erstellt, in dem Konfigurationen, verschlüsselte Passwörter, Notizen und Kartendaten abgelegt werden.

### Benutzeroberfläche und Widgets

- **Moderne UI-Komponenten:**  
  Custom Widgets wie `ModernButton`, `ModernLineEdit` und `ModernLabel` sorgen für ein einheitliches und modernes Design.
- **Kreditkarten-Widget:**  
  Das `CreditCardWidget` visualisiert Kredit- bzw. Debitkartendaten in einem ansprechenden Layout.

### Passwortverwaltung

- **Erstellung und Speicherung:**  
  Neue Passwörter werden zusammen mit einem Titel und Benutzernamen als verschlüsselte JSON-Daten gespeichert.  
  - **Verschlüsselung:** Die gesamte Passwortdatenbank wird mit Fernet verschlüsselt.
- **Anzeige und Bearbeitung:**  
  Gespeicherte Passwörter werden in einem QTreeWidget dargestellt. Einträge können angesehen, bearbeitet oder gelöscht werden.
- **Passwort-Generator:**  
  Die Funktion `generate_password()` erstellt ein sicheres, zufälliges Passwort aus einem festgelegten Zeichenvorrat.

### Notizenverwaltung

- **Erstellung:**  
  Über einen Dialog können neue Notizen (mit Titel und Inhalt) angelegt und gespeichert werden.
- **Bearbeitung und Löschung:**  
  Notizen werden ähnlich wie Passwörter in einem QTreeWidget dargestellt, wobei Bearbeitung und Löschung möglich sind.
- **Verschlüsselung:**  
  Auch Notizen werden mit Fernet verschlüsselt abgelegt.

### Kredit-/Debitkartenverwaltung

- **Karten hinzufügen:**  
  Über einen Dialog können Kartendaten (z. B. Karteninhaber, Kartennummer, Ablaufdatum, CVV) eingegeben werden.
- **Visualisierung:**  
  Das `CreditCardWidget` stellt die Kartendaten visuell ansprechend dar; die Kartennummer wird teilweise maskiert.
- **Sicherheit:**  
  Alle Kartendaten werden verschlüsselt gespeichert.

### Zwei-Faktor-Authentifizierung (2FA)

- **Setup:**  
  Nach der Einrichtung des Master-Passworts kann der Nutzer optional 2FA aktivieren. Dabei wird ein geheimer Schlüssel generiert, ein QR-Code erstellt und der Schlüssel auch manuell angezeigt.
- **Verifizierung:**  
  Beim Login wird – sofern 2FA aktiviert ist – zusätzlich ein TOTP-Code abgefragt, der verifiziert werden muss, bevor der Zugriff gewährt wird.

### Automatische Sperrung

- **Inaktivitäts-Timeout:**  
  Mithilfe eines `QTimer` wird die Anwendung nach einer definierten Inaktivitätsperiode automatisch gesperrt.
- **Event-Filter:**  
  Maus- und Tastatureingaben setzen den Timer zurück, um eine ungewollte Sperrung zu verhindern.

### Backup und Wiederherstellung

- **Backup-Erstellung:**  
  Alle Daten (Passwörter, Notizen, Karten) werden in einem kombinierten JSON-Dokument zusammengeführt, verschlüsselt und in einer Backup-Datei gespeichert.
- **Wiederherstellung:**  
  Über einen Datei-Dialog kann ein Backup ausgewählt, entschlüsselt und in die Anwendung importiert werden.

## Installation und Nutzung

1. **Repository klonen:**

   ```bash
   git clone https://github.com/deinbenutzername/securevault.git
   cd securevault
   
2. **Virtuelle Umgebung erstellen:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Auf Windows: venv\Scripts\activate

3. **Abhängigkeiten installieren:**

   ```bash
   pip install -r requirements.txt

4. **Anwendung starten:**

   ```bash
   python SecureVault.py
