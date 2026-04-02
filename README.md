# SSH Honeypot

A deception-based security tool that pretends to be a real corporate SSH server to trap and log attackers.

Any attacker who connects to this server thinks they are inside a real Ubuntu machine. What they don't know is that every credential they try, every command they run, and every suspicious action they take is being silently logged and flagged.

## What it does

- Presents a fake Ubuntu 22.04 LTS SSH server to the attacker
- Logs every username and password combination attempted
- Gives attackers access to a fully emulated shell with 20 realistic commands
- Detects brute force attacks — flags any IP that fails login 3 or more times
- Generates alerts for high risk commands like sudo, reading /etc/shadow, or downloading files with wget/curl
- Writes everything to two rotating log files with timestamps

## Log Files

**audits.log** — connection attempts, credentials tried, brute force alerts, high risk command alerts

**cmd_audits.log** — every command executed by the attacker inside the shell, with their IP and timestamp

## Requirements

```
pip install paramiko
```

You also need an RSA host key. Generate one like this:

```
ssh-keygen -t rsa -b 2048 -f server.key
```

## How to run

**Open mode — accepts any username and password:**
```
python3 honeypy.py -a 0.0.0.0 -p 2222
```

**Credential mode — only accepts a specific username and password:**
```
python3 honeypy.py -a 0.0.0.0 -p 2222 -u admin -pw admin123
```

For real attacker traffic, deploy on a cloud server and run on port 22. Automated bots scan port 22 on every public IP constantly. You will start seeing real connection attempts within hours.

## Emulated Shell Commands

Once an attacker gets in, they can run these commands:

| Category | Commands |
|---|---|
| Navigation | cd, pwd, ls, ls -la |
| System | whoami, id, hostname, uname -a, uptime, date |
| Network | ifconfig, ip a, netstat -an, ss -an |
| Files | cat jumpbox1.conf, cat network_notes.txt, cat .bash_history, env |
| Process | ps, ps aux |

**Trap commands** — these generate immediate alerts in the logs:

- Any `sudo` command → privilege escalation alert
- `cat /etc/passwd` → user enumeration alert  
- `cat /etc/shadow` → password hash harvesting alert
- `wget` or `curl` → malware download attempt alert

## Project Structure

```
ssh_honeypot/
├── honeypy.py          # Entry point, argument parsing
├── ssh_honeypot.py     # Core logic — server, shell, logging
├── server.key          # RSA private key (not committed, add to .gitignore)
├── server.key.pub      # RSA public key
├── audits.log          # Generated at runtime
└── cmd_audits.log      # Generated at runtime
```

## What I learned building this

This started as a YouTube tutorial by Grant Collins and I kept building on top of it. I learned how SSH actually works under the hood using paramiko's ServerInterface, how to handle multiple connections at the same time with threading, how rotating log files work, and how real honeypots are used by security teams for threat intelligence.

Next step is deploying this on Oracle Cloud Free Tier to collect real attacker data for my portfolio.

## Sources

1. Grant Collins — SSH Honeypot tutorial on YouTube
2. Paramiko documentation — https://www.paramiko.org/
