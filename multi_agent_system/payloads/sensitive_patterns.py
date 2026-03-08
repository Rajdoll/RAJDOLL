"""
Sensitive Data Exposure Detection Patterns
Phase 5 of RAJDOLL Improvement Plan

Target: >80% sensitive data detection rate
Categories:
- API Key Patterns (AWS, Google, Stripe, GitHub, etc.)
- PII Detection (Email, Credit Card, SSN, Phone)
- Credential Patterns
- Secret/Token Patterns
- File Exposure Paths
"""

from dataclasses import dataclass, field
from typing import List, Dict, Pattern
from enum import Enum
import re


class SensitiveDataCategory(Enum):
    API_KEY = "api_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    DATABASE_CREDENTIAL = "database_credential"
    PII = "pii"
    SECRET_TOKEN = "secret_token"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    INTERNAL_INFO = "internal_info"


@dataclass
class SensitivePattern:
    """Pattern definition for sensitive data detection"""
    name: str
    category: SensitiveDataCategory
    pattern: str  # Regex pattern
    severity: str
    description: str
    false_positive_hints: List[str] = field(default_factory=list)


# ============================================================================
# API Key Patterns - 50+ patterns for various services
# ============================================================================

API_KEY_PATTERNS: List[SensitivePattern] = [
    # AWS
    SensitivePattern(
        name="AWS Access Key ID",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="critical",
        description="AWS Access Key ID (starts with AKIA, AIDA, etc.)",
        false_positive_hints=["EXAMPLE", "AKIAIOSFODNN7EXAMPLE"]
    ),
    SensitivePattern(
        name="AWS Secret Access Key",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="critical",
        description="AWS Secret Access Key (40 character base64)"
    ),
    SensitivePattern(
        name="AWS Account ID",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)aws_?account_?id['\"]?\s*[:=]\s*['\"]?(\d{12})['\"]?",
        severity="medium",
        description="AWS Account ID (12 digit number)"
    ),
    SensitivePattern(
        name="AWS Session Token",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)aws_?session_?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        severity="critical",
        description="AWS Session Token"
    ),
    
    # Google Cloud
    SensitivePattern(
        name="Google API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        severity="high",
        description="Google API Key (starts with AIza)"
    ),
    SensitivePattern(
        name="Google OAuth Client ID",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity="medium",
        description="Google OAuth Client ID"
    ),
    SensitivePattern(
        name="Google OAuth Secret",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)client_?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{24})['\"]?",
        severity="high",
        description="Google OAuth Client Secret"
    ),
    SensitivePattern(
        name="Google Cloud Service Account",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com",
        severity="medium",
        description="Google Cloud Service Account Email"
    ),
    SensitivePattern(
        name="Firebase API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)firebase['\"]?\s*[:=]\s*['\"]?AIza[0-9A-Za-z\-_]{35}['\"]?",
        severity="high",
        description="Firebase API Key"
    ),
    
    # Azure
    SensitivePattern(
        name="Azure Storage Account Key",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});",
        severity="critical",
        description="Azure Storage Connection String"
    ),
    SensitivePattern(
        name="Azure AD Client Secret",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)client_?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~._-]{34,})['\"]?",
        severity="high",
        description="Azure AD Application Secret"
    ),
    SensitivePattern(
        name="Azure SAS Token",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"\?sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[A-Za-z0-9%]+",
        severity="high",
        description="Azure Shared Access Signature Token"
    ),
    
    # GitHub
    SensitivePattern(
        name="GitHub Personal Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"ghp_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub Personal Access Token (new format)"
    ),
    SensitivePattern(
        name="GitHub OAuth Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"gho_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub OAuth Access Token"
    ),
    SensitivePattern(
        name="GitHub App Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(ghu|ghs)_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub App User/Server Token"
    ),
    SensitivePattern(
        name="GitHub Refresh Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"ghr_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub Refresh Token"
    ),
    SensitivePattern(
        name="GitHub Legacy Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"[0-9a-f]{40}",
        severity="medium",
        description="GitHub Legacy Personal Access Token (40 char hex)",
        false_positive_hints=["git commit hash"]
    ),
    
    # Stripe
    SensitivePattern(
        name="Stripe Live Secret Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"sk_live_[0-9a-zA-Z]{24,}",
        severity="critical",
        description="Stripe Live Secret Key"
    ),
    SensitivePattern(
        name="Stripe Test Secret Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"sk_test_[0-9a-zA-Z]{24,}",
        severity="medium",
        description="Stripe Test Secret Key"
    ),
    SensitivePattern(
        name="Stripe Live Publishable Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"pk_live_[0-9a-zA-Z]{24,}",
        severity="low",
        description="Stripe Live Publishable Key (public, but indicates production)"
    ),
    SensitivePattern(
        name="Stripe Restricted Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"rk_live_[0-9a-zA-Z]{24,}",
        severity="high",
        description="Stripe Restricted API Key"
    ),
    
    # Slack
    SensitivePattern(
        name="Slack Bot Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        severity="high",
        description="Slack Bot User OAuth Token"
    ),
    SensitivePattern(
        name="Slack User Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        severity="high",
        description="Slack User OAuth Token"
    ),
    SensitivePattern(
        name="Slack Webhook URL",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        severity="high",
        description="Slack Incoming Webhook URL"
    ),
    SensitivePattern(
        name="Slack App Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+",
        severity="high",
        description="Slack App-Level Token"
    ),
    
    # Twilio
    SensitivePattern(
        name="Twilio Account SID",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"AC[a-z0-9]{32}",
        severity="medium",
        description="Twilio Account SID"
    ),
    SensitivePattern(
        name="Twilio Auth Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)twilio.*auth.*token['\"]?\s*[:=]\s*['\"]?([a-z0-9]{32})['\"]?",
        severity="critical",
        description="Twilio Auth Token"
    ),
    
    # SendGrid
    SensitivePattern(
        name="SendGrid API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        severity="high",
        description="SendGrid API Key"
    ),
    
    # Mailgun
    SensitivePattern(
        name="Mailgun API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"key-[0-9a-zA-Z]{32}",
        severity="high",
        description="Mailgun API Key"
    ),
    
    # Square
    SensitivePattern(
        name="Square Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"sq0atp-[0-9A-Za-z\-_]{22}",
        severity="high",
        description="Square Access Token"
    ),
    SensitivePattern(
        name="Square OAuth Secret",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"sq0csp-[0-9A-Za-z\-_]{43}",
        severity="critical",
        description="Square OAuth Secret"
    ),
    
    # PayPal
    SensitivePattern(
        name="PayPal Braintree Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        severity="critical",
        description="PayPal/Braintree Production Access Token"
    ),
    
    # Shopify
    SensitivePattern(
        name="Shopify Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"shpat_[a-fA-F0-9]{32}",
        severity="high",
        description="Shopify Admin API Access Token"
    ),
    SensitivePattern(
        name="Shopify Shared Secret",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"shpss_[a-fA-F0-9]{32}",
        severity="critical",
        description="Shopify Shared Secret"
    ),
    
    # Heroku
    SensitivePattern(
        name="Heroku API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)heroku.*api.*key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        severity="high",
        description="Heroku API Key (UUID format)"
    ),
    
    # NPM
    SensitivePattern(
        name="NPM Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"npm_[A-Za-z0-9]{36}",
        severity="high",
        description="NPM Access Token"
    ),
    
    # Docker Hub
    SensitivePattern(
        name="Docker Hub Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)docker.*token['\"]?\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
        severity="high",
        description="Docker Hub Personal Access Token"
    ),
    
    # DigitalOcean
    SensitivePattern(
        name="DigitalOcean Token",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"(?i)digital.?ocean.*token['\"]?\s*[:=]\s*['\"]?([a-f0-9]{64})['\"]?",
        severity="critical",
        description="DigitalOcean API Token"
    ),
    SensitivePattern(
        name="DigitalOcean OAuth Token",
        category=SensitiveDataCategory.CLOUD_CREDENTIAL,
        pattern=r"doo_v1_[a-f0-9]{64}",
        severity="critical",
        description="DigitalOcean OAuth Token"
    ),
    
    # GitLab
    SensitivePattern(
        name="GitLab Personal Access Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"glpat-[0-9a-zA-Z\-_]{20}",
        severity="critical",
        description="GitLab Personal Access Token"
    ),
    SensitivePattern(
        name="GitLab Pipeline Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"glptt-[0-9a-f]{40}",
        severity="high",
        description="GitLab Pipeline Trigger Token"
    ),
    
    # Bitbucket
    SensitivePattern(
        name="Bitbucket App Password",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)bitbucket.*password['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{24})['\"]?",
        severity="high",
        description="Bitbucket App Password"
    ),
    
    # Sentry
    SensitivePattern(
        name="Sentry DSN",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+",
        severity="medium",
        description="Sentry DSN (Data Source Name)"
    ),
    
    # Datadog
    SensitivePattern(
        name="Datadog API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)datadog.*api.*key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        severity="high",
        description="Datadog API Key"
    ),
    SensitivePattern(
        name="Datadog App Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)datadog.*app.*key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",
        severity="high",
        description="Datadog Application Key"
    ),
    
    # New Relic
    SensitivePattern(
        name="New Relic License Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)new.?relic.*license['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",
        severity="medium",
        description="New Relic License Key"
    ),
    SensitivePattern(
        name="New Relic API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"NRAK-[A-Z0-9]{27}",
        severity="high",
        description="New Relic API Key"
    ),
    
    # Algolia
    SensitivePattern(
        name="Algolia API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)algolia.*api.*key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        severity="high",
        description="Algolia API Key"
    ),
    
    # Cloudflare
    SensitivePattern(
        name="Cloudflare API Key",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)cloudflare.*api.*key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{37})['\"]?",
        severity="high",
        description="Cloudflare API Key"
    ),
    SensitivePattern(
        name="Cloudflare API Token",
        category=SensitiveDataCategory.API_KEY,
        pattern=r"(?i)cloudflare.*token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40})['\"]?",
        severity="high",
        description="Cloudflare API Token"
    ),
]

# ============================================================================
# JWT and Token Patterns
# ============================================================================

TOKEN_PATTERNS: List[SensitivePattern] = [
    # JWT
    SensitivePattern(
        name="JWT Token",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        severity="high",
        description="JSON Web Token (Base64 encoded)"
    ),
    
    # Bearer Token
    SensitivePattern(
        name="Bearer Token",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]+",
        severity="high",
        description="Bearer Authentication Token"
    ),
    
    # Basic Auth
    SensitivePattern(
        name="Basic Auth Header",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
        severity="high",
        description="Basic Authentication Header (Base64)"
    ),
    
    # OAuth Token
    SensitivePattern(
        name="OAuth Access Token",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"(?i)access_?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?",
        severity="high",
        description="OAuth Access Token"
    ),
    SensitivePattern(
        name="OAuth Refresh Token",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"(?i)refresh_?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?",
        severity="high",
        description="OAuth Refresh Token"
    ),
    
    # Session Token
    SensitivePattern(
        name="Session Token",
        category=SensitiveDataCategory.SECRET_TOKEN,
        pattern=r"(?i)session_?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        severity="high",
        description="Session Token"
    ),
]

# ============================================================================
# Private Keys and Certificates
# ============================================================================

PRIVATE_KEY_PATTERNS: List[SensitivePattern] = [
    SensitivePattern(
        name="RSA Private Key",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="critical",
        description="RSA Private Key (PEM format)"
    ),
    SensitivePattern(
        name="DSA Private Key",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN DSA PRIVATE KEY-----",
        severity="critical",
        description="DSA Private Key (PEM format)"
    ),
    SensitivePattern(
        name="EC Private Key",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        severity="critical",
        description="Elliptic Curve Private Key (PEM format)"
    ),
    SensitivePattern(
        name="Private Key (Generic)",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN PRIVATE KEY-----",
        severity="critical",
        description="Generic Private Key (PKCS#8 format)"
    ),
    SensitivePattern(
        name="Encrypted Private Key",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        severity="high",
        description="Encrypted Private Key (may be brute-forced)"
    ),
    SensitivePattern(
        name="OpenSSH Private Key",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="critical",
        description="OpenSSH Private Key"
    ),
    SensitivePattern(
        name="PGP Private Key Block",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="critical",
        description="PGP/GPG Private Key"
    ),
    SensitivePattern(
        name="Certificate",
        category=SensitiveDataCategory.PRIVATE_KEY,
        pattern=r"-----BEGIN CERTIFICATE-----",
        severity="low",
        description="X.509 Certificate (public, but may reveal info)"
    ),
]

# ============================================================================
# Database Connection Strings
# ============================================================================

DATABASE_PATTERNS: List[SensitivePattern] = [
    SensitivePattern(
        name="MySQL Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"mysql://[^:]+:[^@]+@[^/]+/\w+",
        severity="critical",
        description="MySQL connection URL with credentials"
    ),
    SensitivePattern(
        name="PostgreSQL Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"postgres(ql)?://[^:]+:[^@]+@[^/]+/\w+",
        severity="critical",
        description="PostgreSQL connection URL with credentials"
    ),
    SensitivePattern(
        name="MongoDB Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+",
        severity="critical",
        description="MongoDB connection URL with credentials"
    ),
    SensitivePattern(
        name="Redis Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"redis://[^:]*:[^@]+@[^:]+:\d+",
        severity="critical",
        description="Redis connection URL with password"
    ),
    SensitivePattern(
        name="MSSQL Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"(?i)server=[^;]+;.*password=[^;]+",
        severity="critical",
        description="Microsoft SQL Server connection string"
    ),
    SensitivePattern(
        name="Oracle Connection String",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"(?i)oracle://[^:]+:[^@]+@",
        severity="critical",
        description="Oracle database connection string"
    ),
    SensitivePattern(
        name="JDBC URL with Password",
        category=SensitiveDataCategory.DATABASE_CREDENTIAL,
        pattern=r"jdbc:[a-z]+://[^?]+\?.*password=[^&]+",
        severity="critical",
        description="JDBC URL with embedded password"
    ),
]

# ============================================================================
# PII Patterns - Personal Identifiable Information
# ============================================================================

PII_PATTERNS: List[SensitivePattern] = [
    # Email addresses
    SensitivePattern(
        name="Email Address",
        category=SensitiveDataCategory.PII,
        pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        severity="low",
        description="Email address",
        false_positive_hints=["example.com", "test.com", "localhost"]
    ),
    
    # Credit cards (with Luhn validation needed)
    SensitivePattern(
        name="Credit Card (Visa)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        severity="critical",
        description="Visa credit card number"
    ),
    SensitivePattern(
        name="Credit Card (Mastercard)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
        severity="critical",
        description="Mastercard credit card number"
    ),
    SensitivePattern(
        name="Credit Card (Amex)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b3[47][0-9]{13}\b",
        severity="critical",
        description="American Express credit card number"
    ),
    SensitivePattern(
        name="Credit Card (Discover)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
        severity="critical",
        description="Discover credit card number"
    ),
    
    # Social Security Number (US)
    SensitivePattern(
        name="US SSN",
        category=SensitiveDataCategory.PII,
        pattern=r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b",
        severity="critical",
        description="US Social Security Number"
    ),
    
    # Phone numbers (international)
    SensitivePattern(
        name="Phone Number (US)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b",
        severity="medium",
        description="US Phone Number"
    ),
    SensitivePattern(
        name="Phone Number (International)",
        category=SensitiveDataCategory.PII,
        pattern=r"\+[1-9][0-9]{6,14}",
        severity="medium",
        description="International Phone Number (E.164 format)"
    ),
    
    # IP Addresses (not necessarily PII but can be sensitive)
    SensitivePattern(
        name="IPv4 Address",
        category=SensitiveDataCategory.INTERNAL_INFO,
        pattern=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        severity="low",
        description="IPv4 Address"
    ),
    SensitivePattern(
        name="Internal IP (Private)",
        category=SensitiveDataCategory.INTERNAL_INFO,
        pattern=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        severity="medium",
        description="Private/Internal IP Address (RFC 1918)"
    ),
    
    # Passport numbers (common formats)
    SensitivePattern(
        name="Passport Number (Generic)",
        category=SensitiveDataCategory.PII,
        pattern=r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        severity="high",
        description="Passport Number (various countries)"
    ),
    
    # IBAN
    SensitivePattern(
        name="IBAN",
        category=SensitiveDataCategory.PII,
        pattern=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b",
        severity="high",
        description="International Bank Account Number"
    ),
]

# ============================================================================
# Password and Secret Patterns
# ============================================================================

PASSWORD_PATTERNS: List[SensitivePattern] = [
    SensitivePattern(
        name="Password in URL",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"[a-zA-Z]{3,10}://[^:]+:([^@]+)@",
        severity="critical",
        description="Password embedded in URL"
    ),
    SensitivePattern(
        name="Password Assignment",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"(?i)password['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        severity="high",
        description="Password in assignment/config"
    ),
    SensitivePattern(
        name="Password Variable",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"(?i)(password|passwd|pwd|secret|credential)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?",
        severity="high",
        description="Password/secret in variable assignment"
    ),
    SensitivePattern(
        name="Hardcoded Password",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"(?i)(password|passwd|pwd)\s*=\s*['\"]?[\w@#$%^&*!]+['\"]?",
        severity="high",
        description="Hardcoded password"
    ),
    SensitivePattern(
        name="API Secret",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"(?i)(api_?secret|app_?secret|secret_?key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
        severity="high",
        description="API or Application Secret"
    ),
    SensitivePattern(
        name="Encryption Key",
        category=SensitiveDataCategory.PASSWORD,
        pattern=r"(?i)(encryption_?key|aes_?key|crypto_?key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+/=]{16,})['\"]?",
        severity="critical",
        description="Encryption Key"
    ),
]

# ============================================================================
# File Paths for Sensitive Data Discovery
# ============================================================================

SENSITIVE_FILE_PATHS: List[Dict] = [
    # Credentials files
    {"path": "/.aws/credentials", "description": "AWS credentials file", "severity": "critical"},
    {"path": "/.ssh/id_rsa", "description": "SSH private key", "severity": "critical"},
    {"path": "/.ssh/id_ed25519", "description": "SSH private key (Ed25519)", "severity": "critical"},
    {"path": "/.ssh/id_ecdsa", "description": "SSH private key (ECDSA)", "severity": "critical"},
    {"path": "/.ssh/authorized_keys", "description": "SSH authorized keys", "severity": "medium"},
    {"path": "/.netrc", "description": "Network credentials file", "severity": "critical"},
    {"path": "/.npmrc", "description": "NPM configuration (may contain tokens)", "severity": "high"},
    {"path": "/.pypirc", "description": "PyPI configuration (may contain tokens)", "severity": "high"},
    {"path": "/.gem/credentials", "description": "RubyGems credentials", "severity": "high"},
    {"path": "/.docker/config.json", "description": "Docker Hub credentials", "severity": "high"},
    {"path": "/.kube/config", "description": "Kubernetes config", "severity": "critical"},
    
    # History files
    {"path": "/.bash_history", "description": "Bash command history", "severity": "medium"},
    {"path": "/.zsh_history", "description": "Zsh command history", "severity": "medium"},
    {"path": "/.mysql_history", "description": "MySQL command history", "severity": "high"},
    {"path": "/.psql_history", "description": "PostgreSQL command history", "severity": "high"},
    {"path": "/.node_repl_history", "description": "Node.js REPL history", "severity": "medium"},
    {"path": "/.python_history", "description": "Python REPL history", "severity": "medium"},
    
    # IDE/Editor files with possible secrets
    {"path": "/.vscode/settings.json", "description": "VS Code settings", "severity": "low"},
    {"path": "/.idea/workspace.xml", "description": "IntelliJ workspace", "severity": "low"},
    {"path": "/.idea/dataSources.xml", "description": "IntelliJ database config", "severity": "high"},
    
    # Web application sensitive paths
    {"path": "/WEB-INF/web.xml", "description": "Java web.xml config", "severity": "high"},
    {"path": "/WEB-INF/classes/", "description": "Java compiled classes", "severity": "medium"},
    {"path": "/META-INF/context.xml", "description": "Tomcat context config", "severity": "high"},
    {"path": "/crossdomain.xml", "description": "Flash cross-domain policy", "severity": "medium"},
    {"path": "/clientaccesspolicy.xml", "description": "Silverlight access policy", "severity": "medium"},
    
    # Log files (often contain sensitive data)
    {"path": "/var/log/", "description": "System logs directory", "severity": "medium"},
    {"path": "/logs/", "description": "Application logs", "severity": "medium"},
    {"path": "/log/", "description": "Application logs", "severity": "medium"},
    {"path": "/debug.log", "description": "Debug log file", "severity": "high"},
    {"path": "/error.log", "description": "Error log file", "severity": "medium"},
    {"path": "/access.log", "description": "Access log file", "severity": "low"},
    
    # Temp/Cache files
    {"path": "/tmp/", "description": "Temp directory", "severity": "medium"},
    {"path": "/cache/", "description": "Cache directory", "severity": "medium"},
    {"path": "/temp/", "description": "Temp directory", "severity": "medium"},
]

# ============================================================================
# Entropy-based Secret Detection
# ============================================================================

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (for detecting random secrets)"""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy


def is_high_entropy_string(s: str, threshold: float = 4.5) -> bool:
    """Check if string has high entropy (likely a secret)"""
    if len(s) < 16:  # Too short to be meaningful
        return False
    return calculate_shannon_entropy(s) > threshold


# High entropy string pattern (for generic secret detection)
HIGH_ENTROPY_PATTERNS: List[Dict] = [
    {
        "pattern": r"['\"][a-zA-Z0-9+/=]{32,}['\"]",
        "description": "Long base64-like string (potential secret)",
        "min_entropy": 4.0,
    },
    {
        "pattern": r"['\"][a-f0-9]{32,}['\"]",
        "description": "Long hex string (potential hash/key)",
        "min_entropy": 3.5,
    },
    {
        "pattern": r"['\"][a-zA-Z0-9_\-]{20,}['\"]",
        "description": "Long alphanumeric string (potential token)",
        "min_entropy": 4.0,
    },
]

# ============================================================================
# Compile all patterns
# ============================================================================

ALL_SENSITIVE_PATTERNS: List[SensitivePattern] = (
    API_KEY_PATTERNS + 
    TOKEN_PATTERNS + 
    PRIVATE_KEY_PATTERNS + 
    DATABASE_PATTERNS + 
    PII_PATTERNS + 
    PASSWORD_PATTERNS
)


def get_compiled_patterns() -> Dict[str, re.Pattern]:
    """Get all patterns compiled as regex objects"""
    compiled = {}
    for pattern in ALL_SENSITIVE_PATTERNS:
        try:
            compiled[pattern.name] = re.compile(pattern.pattern, re.IGNORECASE)
        except re.error as e:
            print(f"Warning: Invalid regex for {pattern.name}: {e}")
    return compiled


# ============================================================================
# Summary Statistics
# ============================================================================

def get_sensitive_pattern_stats() -> Dict:
    """Get statistics about sensitive data patterns"""
    by_category = {}
    for pattern in ALL_SENSITIVE_PATTERNS:
        cat = pattern.category.value
        by_category[cat] = by_category.get(cat, 0) + 1
    
    return {
        "total_patterns": len(ALL_SENSITIVE_PATTERNS),
        "api_key_patterns": len(API_KEY_PATTERNS),
        "token_patterns": len(TOKEN_PATTERNS),
        "private_key_patterns": len(PRIVATE_KEY_PATTERNS),
        "database_patterns": len(DATABASE_PATTERNS),
        "pii_patterns": len(PII_PATTERNS),
        "password_patterns": len(PASSWORD_PATTERNS),
        "sensitive_file_paths": len(SENSITIVE_FILE_PATHS),
        "by_category": by_category,
    }


if __name__ == "__main__":
    stats = get_sensitive_pattern_stats()
    print("=" * 60)
    print("PHASE 5: Sensitive Data Exposure Detection")
    print("=" * 60)
    print(f"API Key Patterns:              {stats['api_key_patterns']}")
    print(f"Token Patterns:                {stats['token_patterns']}")
    print(f"Private Key Patterns:          {stats['private_key_patterns']}")
    print(f"Database Patterns:             {stats['database_patterns']}")
    print(f"PII Patterns:                  {stats['pii_patterns']}")
    print(f"Password Patterns:             {stats['password_patterns']}")
    print(f"Sensitive File Paths:          {stats['sensitive_file_paths']}")
    print("-" * 60)
    print(f"TOTAL PATTERNS:                {stats['total_patterns']}")
    print("=" * 60)
    print("\nBy Category:")
    for cat, count in stats['by_category'].items():
        print(f"  {cat}: {count}")
