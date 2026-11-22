"""
Management command to seed sample cybersecurity knowledge data.
Run: python manage.py seed_knowledge
"""
from django.core.management.base import BaseCommand
from knowledgegraph.models import CyberKnowledge


SEED_DATA = [
    {
        "threat_name": "SQL Injection",
        "threat_type": "Web Application Attack",
        "description": "SQL Injection is a code injection technique that attackers use to insert malicious SQL statements into input fields for execution by the underlying SQL database.",
        "attack_method": "Attacker inserts or 'injects' malicious SQL code via user input fields, URLs, or HTTP headers. The database executes the injected code, allowing data extraction, modification, or deletion.",
        "prevention": "Use parameterized queries/prepared statements. Implement input validation and sanitization. Apply principle of least privilege. Use Web Application Firewalls (WAF). Regularly audit and update database permissions.",
        "severity": "critical",
        "risk_score": 9.8,
        "related_vulnerabilities": "OWASP A03:2021 Injection, CWE-89",
        "cve_references": "CVE-2023-23503, CVE-2022-22965",
    },
    {
        "threat_name": "Cross-Site Scripting (XSS)",
        "threat_type": "Web Application Attack",
        "description": "XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users. Executed scripts can steal session tokens, deface websites, or redirect users.",
        "attack_method": "Malicious scripts are injected into trusted websites. Types include Stored XSS (persisted in database), Reflected XSS (reflected off web server), and DOM-based XSS.",
        "prevention": "Encode output data. Validate and sanitize all user inputs. Implement Content Security Policy (CSP). Use HTTPOnly and Secure cookie flags. Apply output encoding specific to HTML context.",
        "severity": "high",
        "risk_score": 7.5,
        "related_vulnerabilities": "OWASP A07:2021, CWE-79",
        "cve_references": "CVE-2023-0179, CVE-2022-1011",
    },
    {
        "threat_name": "Ransomware",
        "threat_type": "Malware",
        "description": "Ransomware is malicious software that encrypts a victim's files or locks their device, demanding payment (ransom) for the decryption key or restoration of access.",
        "attack_method": "Delivered via phishing emails, malicious downloads, RDP exploitation, or supply chain attacks. Once executed, it encrypts files using strong cryptography (AES-256) and demands Bitcoin payment.",
        "prevention": "Maintain offline backups (3-2-1 rule). Keep software updated. Use EDR solutions. Implement email filtering. Segment networks. Train users on phishing. Disable RDP if unused.",
        "severity": "critical",
        "risk_score": 9.5,
        "related_vulnerabilities": "CWE-311, CVE-2017-0144 (EternalBlue)",
        "cve_references": "CVE-2021-34527, CVE-2017-0144",
    },
    {
        "threat_name": "Phishing Attack",
        "threat_type": "Social Engineering",
        "description": "Phishing is a cybercrime technique where attackers disguise themselves as trusted entities to steal sensitive information such as credentials, credit card numbers, or install malware.",
        "attack_method": "Attackers send fraudulent emails, SMS (smishing), or voice calls (vishing) mimicking legitimate organizations. Links redirect to fake login pages harvesting credentials.",
        "prevention": "Implement email authentication (SPF, DKIM, DMARC). Use multi-factor authentication. Train employees regularly. Deploy email filtering solutions. Use URL reputation services.",
        "severity": "high",
        "risk_score": 8.0,
        "related_vulnerabilities": "Social engineering, credential theft, MITM",
        "cve_references": "",
    },
    {
        "threat_name": "DDoS Attack",
        "threat_type": "Denial of Service",
        "description": "Distributed Denial of Service attacks overwhelm target servers with traffic from multiple sources (botnet), making services unavailable to legitimate users.",
        "attack_method": "Botnets of compromised devices send massive traffic floods (volumetric), exploit protocol weaknesses (protocol attacks), or target application layer resources (layer 7 attacks).",
        "prevention": "Use DDoS protection services (Cloudflare, AWS Shield). Implement rate limiting. Configure traffic filtering. Use Content Delivery Networks. Set up geo-blocking. Deploy Anycast network diffusion.",
        "severity": "high",
        "risk_score": 7.8,
        "related_vulnerabilities": "CWE-400, Botnet infrastructure",
        "cve_references": "",
    },
    {
        "threat_name": "Man-in-the-Middle Attack",
        "threat_type": "Network Attack",
        "description": "MITM attacks intercept communications between two parties, allowing attackers to eavesdrop, modify data, or inject malicious content without either party's knowledge.",
        "attack_method": "ARP poisoning, DNS spoofing, SSL stripping, rogue Wi-Fi access points, or BGP hijacking. Attacker positions themselves between client and server to intercept traffic.",
        "prevention": "Use end-to-end encryption (TLS 1.3+). Implement certificate pinning. Enable HSTS. Use VPNs on public networks. Validate SSL certificates. Deploy MFA.",
        "severity": "high",
        "risk_score": 8.2,
        "related_vulnerabilities": "CWE-300, ARP Spoofing, DNS Cache Poisoning",
        "cve_references": "CVE-2014-0160",
    },
    {
        "threat_name": "Zero-Day Vulnerability",
        "threat_type": "Vulnerability Exploitation",
        "description": "A zero-day vulnerability is a software flaw unknown to the vendor that attackers exploit before a patch is available, leaving systems with zero days of protection.",
        "attack_method": "Attackers discover undisclosed flaws through fuzzing, reverse engineering, or dark web purchase. Exploits are used before vendor awareness, maximizing damage window.",
        "prevention": "Defense-in-depth strategy. Network segmentation. Behavioral analysis tools. Intrusion detection systems. Threat intelligence feeds. Patch management program. Application whitelisting.",
        "severity": "critical",
        "risk_score": 9.9,
        "related_vulnerabilities": "Unknown CVEs, 0-day markets",
        "cve_references": "CVE-2023-20963, CVE-2022-41040",
    },
    {
        "threat_name": "Privilege Escalation",
        "threat_type": "Post-Exploitation",
        "description": "Privilege escalation occurs when an attacker gains elevated access beyond what is permitted, allowing them to perform unauthorized actions including accessing sensitive data or installing malware.",
        "attack_method": "Vertical escalation: lower privilege user gaining admin rights. Horizontal escalation: accessing another user's resources. Methods include kernel exploits, SUID abuse, token manipulation, and sudo misconfigurations.",
        "prevention": "Apply principle of least privilege. Regularly audit permissions. Keep OS patched. Use Privileged Access Management (PAM). Monitor authentication logs. Implement just-in-time access.",
        "severity": "high",
        "risk_score": 8.5,
        "related_vulnerabilities": "CWE-269, Kernel exploits, Sudo vulnerabilities",
        "cve_references": "CVE-2021-4034, CVE-2022-0847",
    },
    {
        "threat_name": "Brute Force Attack",
        "threat_type": "Authentication Attack",
        "description": "Brute force attacks attempt to gain unauthorized access by systematically trying all possible passwords or encryption keys until the correct one is found.",
        "attack_method": "Dictionary attacks use common passwords. Credential stuffing uses leaked username/password pairs. Rainbow table attacks use precomputed password hashes. Tools: Hydra, John the Ripper, Hashcat.",
        "prevention": "Implement account lockout policies. Use MFA. Enforce strong password policies. Deploy CAPTCHA. Monitor and alert on failed login attempts. Use rate limiting. Implement geo-blocking.",
        "severity": "medium",
        "risk_score": 6.5,
        "related_vulnerabilities": "CWE-307, CWE-521, Credential stuffing",
        "cve_references": "",
    },
    {
        "threat_name": "Remote Code Execution (RCE)",
        "threat_type": "Critical Vulnerability",
        "description": "RCE vulnerabilities allow attackers to run arbitrary code on a target machine remotely, potentially leading to full system compromise.",
        "attack_method": "Exploiting deserialization flaws, buffer overflows, injection vulnerabilities, or misconfigured APIs. Attackers craft malicious payloads that execute commands on the target server.",
        "prevention": "Keep all software patched. Use Web Application Firewalls. Implement input validation. Run services with minimal privileges. Use containerization. Enable ASLR and DEP/NX. Monitor for anomalous process execution.",
        "severity": "critical",
        "risk_score": 10.0,
        "related_vulnerabilities": "CWE-94, CWE-502, Log4Shell",
        "cve_references": "CVE-2021-44228, CVE-2021-26855",
    },
    {
        "threat_name": "Cross-Site Request Forgery (CSRF)",
        "threat_type": "Web Application Attack",
        "description": "CSRF tricks authenticated users into executing unwanted actions on web applications they are currently authenticated to.",
        "attack_method": "Attacker crafts malicious link or page that sends authenticated requests on behalf of victim. Exploits browser's automatic inclusion of cookies in cross-origin requests.",
        "prevention": "Implement CSRF tokens (synchronized token pattern). Use SameSite cookie attribute. Verify Origin and Referer headers. Require re-authentication for sensitive actions. Use custom request headers for AJAX.",
        "severity": "medium",
        "risk_score": 6.5,
        "related_vulnerabilities": "OWASP A01:2021, CWE-352",
        "cve_references": "",
    },
    {
        "threat_name": "Advanced Persistent Threat (APT)",
        "threat_type": "State-Sponsored Attack",
        "description": "APTs are prolonged, targeted cyberattacks by sophisticated threat actors (often nation-states) who gain access to networks and remain undetected for extended periods.",
        "attack_method": "Spear phishing for initial access, lateral movement through the network, establishing persistence via backdoors, data exfiltration over long periods. Well-resourced, patient attackers.",
        "prevention": "Zero-trust architecture. Network segmentation. Advanced EDR/XDR solutions. User and Entity Behavior Analytics (UEBA). Threat hunting programs. Regular security audits. Incident response planning.",
        "severity": "critical",
        "risk_score": 9.7,
        "related_vulnerabilities": "Multiple CVEs, Supply chain attacks",
        "cve_references": "CVE-2020-1472, CVE-2020-0688",
    },
]


class Command(BaseCommand):
    help = 'Seeds the database with sample cybersecurity knowledge data'

    def handle(self, *args, **options):
        created = 0
        for item in SEED_DATA:
            _, was_created = CyberKnowledge.objects.get_or_create(
                threat_name=item['threat_name'],
                defaults=item
            )
            if was_created:
                created += 1
                self.stdout.write(self.style.SUCCESS(f'  + {item["threat_name"]}'))
            else:
                self.stdout.write(f'  ~ {item["threat_name"]} (already exists)')

        self.stdout.write(self.style.SUCCESS(
            f'\nSeeding complete: {created} new entries created, '
            f'{len(SEED_DATA) - created} already existed.'
        ))
