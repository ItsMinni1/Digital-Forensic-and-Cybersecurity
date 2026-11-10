Case Study of a MITM incident

BGP Hijacking and DNS Spoofing of MyEtherWallet (2018)

# Incident Overview: 
## Target: Users of MyEtherWallet -> a popular web-based Ethereum wallet interface.

## Attacker: An unknown threat actor who executed a multi-stage Border Gateway Protocol (BGP) Route Hijack combined with DNS spoofing.

## How the attack executed:
On April 24, 2018, the attacker compromised or misconfigured an Autonomous System (AS209242) and published malicious BGP routes for IP addresses belonging to Amazon Web Services (AWS) Route 53 (specifically Amazon’s authoritative DNS server block 205.251.192.0/23). Major transit providers (e.g., eNet) accepted and propagated the fake routes across the internet.
All internet traffic destined for AWS Route 53 DNS servers was silently rerouted to server infrastructure controlled by the attacker in an Equinix data center in Chicago.
When users navigated to myetherwallet.com, their DNS requests were intercepted by the attacker’s rogue DNS server. The rogue server answered with an IP address pointing to a fake, cloned version of the MEW website hosted on the attacker’s server.
Because the fake site could not generate a valid TLS/SSL certificate signed by a trusted Authority for myetherwallet.com, it presented a self-signed HTTPS certificate, relying on users to click past browser TLS warnings.

# What the attacker obtained: 
Users who ignored the TLS browser security warning entered their private keys, mnemonic seed phrases, and passphrase credentials directly into the fake interface.
The attacker automatically executed balance transfers using the stolen private keys, draining cryptocurrency wallets. Approximately $152,000 in Ethereum (ETH) (and millions in custom ERC-20 tokens at the time) was stolen within a 2-hour window before BGP route announcements were corrected.

# Preventive Controls:
### Resource Public Key Infrastructure (RPKI) with Route Origin Authorization (ROA)
RPKI is a cryptographic public key infrastructure framework designed to secure the Internet's BGP routing architecture. Network operators sign a Route Origin Authorization (ROA) object linking their IP address prefixes to their authorized Autonomous System Number (ASN). Upstream Tier-1 and Tier-2 Internet Service Providers (ISPs) implementing Route Origin Validation (ROV) automatically drop unauthorized BGP route announcements that lack a valid cryptographic signature, stopping BGP-based MITM redirection at the network edge.
RPKI standards and software implementations (such as routinator, Krill, or StayRTR) are open-source and maintained by Regional Internet Registries (RIRs) like ARIN, RIPE NCC, and APNIC.
For Enterprise / Hosting Level: Free to set up via the web portal of the appropriate Regional Internet Registry (e.g., ARIN) by publishing ROA records (takes ~2–4 technical labor hours).
For ISP / Network Provider Level: Requires network engineer time to configure BGP routers to perform Route Origin Validation (ROV). For a medium-sized ISP, this involves approximately 20 to 40 engineering hours for configuration and testing, translating to an operational labor cost of roughly $2,500 – $7,000 USD in staff time, with zero ongoing software licensing costs.

Citation Sources

    Kentik Network Analytics: "BGP Hijacking: Understanding Threats to Internet Routing".

    Noction Architecture Guide: "What is BGP Hijacking? Prevention and defense mechanisms (RPKI Analysis)".