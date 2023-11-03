# OSCP Checklist
TKTK.

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
- TKTK
- Ensure that IPs, ports, etc match. For instance, go over the IPs and make sure they all actually ARE CDE IPs. If there's question, hash it out with the client.

## Preparation
- Divide the list of IPs into "external" (i.e., DMZ) and "internal" (unreachable) - e.g., `scope-192.lst` for external, and `scope-172.lst` for internal systems
- Make a directory structure for the test:
```
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
  ```
  masscan -iL scope-192.lst -p0-65535 -oG scans/masscan-scope-192.lst-allports.gnmap
  ```
- [ ] Ping sweep - not necessary as OSCP typically gives IP scope
  ```
  nmap -iL scope-192.lst -sn -T4 -oA scans/nmap-scope-192.lst-sn -v
  ```
- [ ] Kick off a "flagship" top 1024 scan. Don't forget to log it in case the scans hang up. Increase to `-T5` if you're feeling adventurous:
  ```
  # Nmap with no ping (-Pn), banner grab (-sV), default scripts (-sC). Logs to a tee'd output file.
  nmap -iL scope-192.lst -Pn -sVC -T5 -v -oA scans/nmap-scope-192-Pn-sVC-T5 | tee logs/nmap.log
  # For a larger network with lots of hosts (not OSCP :D)
  nmap -iL scope-internal.lst -sV -sC -oA scans/nmap-sV-sC --open --max-retries=1 --min-parallelism=128 --min-hostgroup=128 -v | tee logs/nmap.log
  ```
  - [ ] Check the `masscan` output for additional ports missed in the top 1000 port scan above, and rescan those
- [ ] Kick off a UDP scan. Key protocols to look out for: SNMP, TFTP, NTP
  ```
  nmap -iL scope-192.lst -sU -T5 -v -oA scans/nmap-scope-192-Pn-sU -Pn    # Optional: can specify --top-ports=25 to do faster scan w/ smaller scope
  ```
- [ ] Parse through open ports with: https://raw.githubusercontent.com/altjx/ipwn/master/nmap_scripts/nmapscrape.rb
  - This will generate a `./scans/open-ports` directory that will be referenced below
- [ ] Scan for SMB and for SMB Signing:
  ```
  crackmapexec smb ./scans/open-ports/445.txt | tee enum/cme-smb-scan.log
  ```
- [ ] Scan for top MS vulns:
  ```
  nmap -iL open-ports/445.txt -p445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010 -v | tee scans/nmap-smb-vulns.log
  ```
- [ ] Begin web enumeration
  - [ ] Manually browse to each web application
  - [ ] Check raw responses to identify web stack, redirects, etc. -- `web02` used as example of TCP/80 open on a web site:
  ```
  curl -I http://web02    # Fetches only the headers, may need -k for https
  ```
  - [ ] Run `nikto` to automate a lot of the checks:
  ```
  nikto -host http://web02 -output enum/nikto-http-web02
  ```
  - [ ] If there are a lot of web services, you may want to run [`aquatone`](https://github.com/michenriksen/aquatone), [`gowitness`](https://github.com/sensepost/gowitness), etc.
  ```
  cat ./scans/open-ports/80.txt | /opt/aquatone -ports large -out enum/aquatone
  ```
  - [ ] 
- [ ] Check for Jenkins instances. Typically runs on TCP/8080 (check `aquatone` output).
- [ ] SNMP checks
- [ ] `rpcclient` Check for NULL sessions, enum info if auth'd
- [ ] KRB guessing
- [ ] Check for database issues:
  - PostgreSQL: check for unauthenticated instances with `postgres:` (MSF module: `auxiliary/scanner/postgres/postgres_login`)
    - **This results in automatic RCE via `COPY TO` if version is >=9.3!**
  - MSSQL: `sa:sa`, `sa:`, and similar (MSF module: `auxiliary/scanner/mssql/mssql_login`)
- [ ] Check for port 12721, java deserialization on vCenter. Can use `nmap -sV --script rmi-* ip` to validate

## Getting a Foothold
- [ ] Begin running [Responder](https://github.com/SpiderLabs/Responder):
  ```
  apt update && apt install -y responder
  responder -I eth0 -wrf
  ```
- [ ] Run [mitm6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/):
  ```
  pip install mitm6
  mitm6 -i eth0 -d firenation.com --debug 
  ```
  *Note: Every time I've run this, it has caused network disruptions. Proceed with caution and check out params `-hw` and `-hb`*    
- [ ] Relay NTLM authentication from the above poisoning (this specifically is for `mitm6`)
  ```
  ## Should relay to victim via SMB. Needs local admin (I think maybe RID500...need to verify)
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -of net-ntlmv2.hsh                   # Attempt to dump SAM 
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -of net-ntlmv2.hsh -c "systeminfo"   # Runs "systeminfo". Caught by CrowdStrike.
  ## LDAPS NTLM relay (patches may fix this!). Any Domain User can add up to 10 computers by default. Compy can be used for BloodHound.
  ntlmrelayx.py --ipv6 -wh wpad.firenation.com -t ldaps://dc.firenation.com --add-computer
  ##
  ```
- Multirelay with [new features for `ntlmrelayx.py`](https://www.secureauth.com/blog/what-old-new-again-relay-attack)
- Check for webmail/Exchange -- mailsniper, ruler, etc
    - https://github.com/sensepost/ruler/wiki/Homepage
    - Log in to O365 or internal and own their mailbox
- Check for Zerologon: https://www.secura.com/blog/zero-logon

## Local PrivEsc
- Local priv esc: 
    - https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
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
192.168.215.70  corp.com dc1.corp.com
```
- [ ] Run BloodHound!!
  - Mark owned users and computers as you compromise them (old version :/)
  - Identify abusable attack paths
- [ ] Kerberoasting
- [ ] AS-REP roasting
- [ ] With owned accounts, log in to email and look for secrets. Try `CredSniper.ps1`. Also look at Teams, Skype history, etc. for juicies
- [ ] Identify servers AND users that are configured for unconstrained delegation
- [ ] Identify servers AND users that are configured for constrained delegation
- [ ] Check for SMB signing not required and such. Consider the printer bug and see if you can relay that.
- [ ] Run `CredNinja.py` against the network with the compromised accounts. See if you have local admin and can keep dumping hashes
- [ ] Check for SMB servers. Use `smbclient.py` and `crackmapexec` to search for interesting files in those shares that you can access
```
crackmapexec smb -u USER -p PASS -d domain.org --shares 445.lst | tee enum/cme-enumshares.lst
grep READ enum/cme-enumshares.lst
```
- [ ] Check domain 

## Lateral Movement to Restricted Segment
Assuming it's a PCI test, I'll use CDE for restricted segment:
- [ ] Port scan from every machine to target network although this may be inefficient
- [ ] Check for split tunnel VPNs - attempt to enumerate workstations for other interfaces that could be in CDE
- [ ] Identify admins or users with access to CDE and keylog for creds
- [ ] Check netstats from jumpboxes and so forth into the CDE (ex. steal an RDP session via `tscon` or similar)
- [ ] Folder sharing through RDP sessions
- [ ] Pivot through a DC -- many times a DC will have more access into a CDE
- [ ] Identify network devices that could be on the edge of the CDE and see if you can log in
  - [ ] Target network admins to see if you can SSH into FWs and such
- [ ] Check for domain trusts and see if you can abuse

## Persistence & Data Exfil

