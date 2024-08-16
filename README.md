# OSCP Exam Checklist
This guide & checklist is recommended resources and steps for targeting the OSCP exam & certification challenge.

The focus here is on steps to take, tools to run, things to check. Other files in this repo have the specific commands to run. I've linked to those where possible.

## Things to Not Forget
- Don't dive too deep into any rabbit holes!
  - Make note of it, come back to it if needed.
- Always have some enumeration going on in the background.
  - I tend to recommend doing this in an iterative fashion.
  - Examples:
    - Run exhaustive scans (all ports TCP/UDP)
    - Dirbust all web applications
    - Brute force guess passwords (SMB, HTTP, RDP, SSH, FTP, etc.)

## Notes for Reporting
- Read the [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) a few days before exam, and _just_ before you begin so you remember the limitations, restrictions, and reporting requirements.
- Personally, for OffSec exams, I always take notes directly in [the reporting template they provide](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx). Just be sure to take copious notes and screenshots.
- Take multiple screenshots, especially of web applications. Be mindful of the screenshotting requiremnts (`ipconfig`, `whoami`, etc.) in an interactive shell.

## Preparation
- [ ] Divide the list of IPs into "external" (i.e., DMZ) and "internal" (unreachable) - e.g., `scope-192.lst` for external, and `scope-172.lst` for internal systems
- [ ] Make a directory structure for the test:
  ```bash
  mkdir ./oscp-exam
  cd oscp-exam
  mkdir enum    # This will be for enumeration output (e.g., nikto, smb scans, etc.)
  mkdir scans   # All masscan/nmap scans will go here
  mkdir loot    # Passwords, hashes, keys, etc.
  mkdir srv     # Files we want to host via HTTP/SMB
  mkdir logs    # Log files for scans, etc.
  ```

## Network Scanning & Enumeration
- [ ] Masscan the target environment:
  ```bash
  masscan -iL scope-192.lst -p0-65535 -oG scans/masscan-scope-192.lst-allports.gnmap
  ```
- [ ] OPTIONAL: Ping sweep (not always necessary as OSCP typically gives IP scope)
  ```bash
  nmap -iL scope-192.lst -sn -T4 -oA scans/nmap-scope-192.lst-sn -v
  ```
- [ ] Kick off a "flagship" top 1000 port scan. Don't forget to log it in case the scans hang up. Increase to `-T5` if you're feeling adventurous:
  ```bash
  # Nmap with no ping (-Pn), banner grab (-sV), default scripts (-sC). Logs to a tee'd output file.
  nmap -iL scope-192.lst -Pn -sVC -T4 -v -oA scans/nmap-scope-192-Pn-sVC-T5 | tee logs/nmap.log
  # For a larger network with lots of hosts (not OSCP :D)
  nmap -iL scope-internal.lst -sV -sC -oA scans/nmap-sV-sC --open --max-retries=1 --min-parallelism=128 --min-hostgroup=128 -v | tee logs/nmap.log
  ```
  - [ ] Check the `masscan` output for additional ports missed in the top 1000 port scan above, and rescan those
- [ ] Kick off a UDP scan. Key protocols to look out for: SNMP (UDP/161), TFTP (UDP/69), NTP (UDP/123)
  ```bash
  nmap -iL scope-192.lst -sU -T5 -v -oA scans/nmap-scope-192-Pn-sU -Pn    # Optional: can specify --top-ports=25 to do faster scan w/ smaller scope
  ```
- [ ] Parse through open ports with: https://raw.githubusercontent.com/altjx/ipwn/master/nmap_scripts/nmapscrape.rb
  - This will generate a `./scans/open-ports` directory that will be referenced below
- [ ] Scan for SMB and for SMB Signing:
  ```bash
  crackmapexec smb ./scans/open-ports/445.txt | tee enum/cme-smb-scan.log
  ```
- [ ] Scan for old critical Microsoft SMB vulnerabilities:
  ```bash
  nmap -iL open-ports/445.txt -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010 -v | tee scans/nmap-smb-vulns.log
  ```
- [ ] SNMP checks
- [ ] `rpcclient` Check for NULL sessions, enumerate info if you get a successful auth
- [ ] Kerberos username guessing (KRB guessing) if you need to obtain a user list
- [ ] Check for database issues:
  - PostgreSQL: check for unauthenticated instances with `postgres:` (MSF module: `auxiliary/scanner/postgres/postgres_login`)
    - *This results in automatic RCE via `COPY TO` if version is >=9.3!*
  - MSSQL: `sa:sa`, `sa:`, and similar (MSF module: `auxiliary/scanner/mssql/mssql_login`)
- [ ] Check for port 12721, java deserialization on vCenter. Can use `nmap -sV --script rmi-* ip` to validate

## Web Attacks
- [ ] Fire up Burp Suite, and configure the scope to include all web services
- [ ] Manually browse to each web application through Burp to log all requests and build out a tree in the `Target` > `Site Map` tab.
- [ ] Check raw responses to identify web stack, redirects, etc. -- `web02` used as example of TCP/80 open on a web site:
  ```bash
  curl -I http://web02    # Fetches only the headers, may need -k for https
  ```
- [ ] Run `nikto` to automate a lot of the checks:
  ```bash
  nikto -host http://web02 -output enum/nikto-http-web02
  ```
- [ ] [NON-OSCP] If there are a lot of web services, you may want to run [`httpx`](https://github.com/projectdiscovery/httpx) or [`aquatone`](https://github.com/michenriksen/aquatone), [`gowitness`](https://github.com/sensepost/gowitness), etc.
  ```bash
  cat ./scans/open-ports/80.txt | /opt/aquatone -ports large -out enum/aquatone
  ```
- [ ] Run `gobuster` or `dirbuster`, etc. to check for web apps, hidden files/folders, and goodies:
  ```
  apt install gobuster
  gobuster dir -u http://web01/ -x php,asp,aspx,txt,html,htm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/gobuster-web01.out
  ```
- [ ] Check for Jenkins instances. Typically runs on TCP/8080 (check `aquatone` output).

## Local PrivEsc
- Windows:
    - Reference the [HackTricks Windows priv esc checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
    - https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
    - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
- Check common places for creds:
    - Windows:
      - Sticky notes in sqlite at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
      - OneNote
    - Linux:
      - `.bashrc` files
      - Log files

## Domain PrivEsc
Assuming you have compromised a domain user or domain-joined system:
- [ ] Edit `/etc/hosts` file to have the name of the domain for the DC. If you know other domain-joined hostnames, add those as well. Example (note the alias):
  ```
  ## OSCP HOSTS ##
  192.168.200.10  corp.com dc1.corp.com dc1
  192.168.200.20  files01.corp.com files01
  192.168.200.21  client01.corp.com client01
  ```
- [ ] Run BloodHound!!
  - [ ] Mark owned users and computers as you compromise them (only in old version atm :/)
  - [ ] Identify abusable attack paths
  - [ ] Check for servers AND users that are configured for unconstrained delegation
  - [ ] Check for servers AND users that are configured for constrained delegation
- [ ] Roasting Kerberos. I like to use `impacket` for this, but you can definitely use `Rubeus` or various PowerShell tooling if you get a foothold on a Windows box.
  - [ ] Kerberoast: 
    ```shell
    impacket-GetUserSPNs corp.com/mayh3m:'P@ssw0rd!' -outputfile loot/kerber.rst
    ```
  - [ ] AS-REP roast:
    ```shell
    impacket-GetNPUsers corp.com/mayh3m:'P@ssw0rd!' -outputfile loot/asrep.rst
    ```
  - [ ] Cracking offline. With OSCP, if a hash is intended to be crackable, you should probably be ok using `rockyou.txt` with default rules.
    ```shell
    # May need to gunzip rockyou.txt first
    gunzip /usr/share/wordlists/rockyou.txt.gz
    john loot/kerber.rst --wordlist=/usr/share/wordlists/rockyou.txt --rules
    john loot/asrep.rst --wordlist=/usr/share/wordlists/rockyou.txt --rules
    ```
- [ ] Enumerate SMB servers with all creds. Use `smbclient.py` and `crackmapexec` to search for interesting files in those shares that you can access
  ```shell
  crackmapexec smb -u loot/users.lst -p loot/cleartext-passwords.txt -d corp.com scope-172.lst
  crackmapexec smb -u USER -p PASS -d corp.com --shares scope-172.lst | tee enum/cme-enumshares.lst
  grep READ enum/cme-enumshares.lst
  ```
