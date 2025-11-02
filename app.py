import sys
import os

# CRITICAL: Add our custom imghdr module to the path BEFORE any mitmproxy imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
import json
import base64
import hashlib
import logging
import asyncio
import tempfile
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional, Tuple, Union, Any

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import regex as re
from playwright.async_api import async_playwright

# Now we can safely import mitmproxy (our custom imghdr is already in the path)
from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import threading
import jwt

# Import our custom views
from custom_views import load as load_custom_image_view

# Import pattern manager for enhanced detection
from pattern_importer import get_enhanced_patterns

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
load_dotenv()

# Global state for mitmproxy
mitm_thread = None
mitm_running = False

# Custom patterns for detecting potential secrets (will be enhanced with GitLeaks patterns)
CUSTOM_SECRET_PATTERNS = {
    # API Keys and Tokens (Gitleaks-inspired patterns)
    'api_key': r'(?i)(?:api[_-]?key|apikey|api[_-]?token|api[_-]?secret)[=: ]*[\'\"]?([a-z0-9_\-]{20,})[\'\"]?',
    'jwt_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # Stricter - min 10 chars per section
    'bearer_token': r'bearer[\s=:]+([a-zA-Z0-9_\-]{20,})',
    'oauth_token': r'[0-9]+-[0-9A-Za-z_]{40}',
    'hardcoded_creds': r'(?i)(?:username|user|password|pass|secret|key|token)[\s=:]+\s*[\'\"]([a-zA-Z0-9_\-@\.]{12,})[\'\"]',
    
    # Cloud Provider Credentials (Gitleaks-inspired patterns)
    'aws_key': r'AKIA[0-9A-Z]{16}',  # More accurate - AWS keys always start with AKIA
    'aws_secret': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',  # Context-aware AWS secret
    'aws_account_id': r'\b(aws[_-]?account[_-]?id|account[_-]?id|aws[_-]?id)[=: ]*[\'\"]?([0-9]{4}[\-]?[0-9]{4}[\-]?[0-9]{4})[\'\"]?',
    'aws_credentials_block': r'\[default\][\s\S]*?aws_access_key_id\s*=\s*([A-Z0-9]{20})[\s\S]*?aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})',
    'aws_config': r'\[profile [^\]]+\][\s\S]*?aws_access_key_id\s*=\s*([A-Z0-9]{20})[\s\S]*?aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})',
    'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'google_service_account': r'"type":\s*"service_account"[\s\S]*?"project_id":\s*"[^"]*"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY-----',
    'google_vertex_api_key': r'(?i)vertex[_-]?(?:ai[_-]?)?(?:api[_-]?)?key[=: ]*[\'\"]?(AIza[0-9A-Za-z\-_]{35})[\'\"]?',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'heroku_api_key': r'[h|H][e|E][r|R][o|O][k|K][u|U][\s\-]?[a|A][p|P][i|I][\s\-]?[k|K][e|E][y|Y][\s\-\:]*[\'\"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[\'\"]?',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'mailchimp_api_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'stripe_key': r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}',  # Catches both secret and publishable keys
    'stripe_restricted_key': r'rk_(?:test|live)_[0-9a-zA-Z]{24,}',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',  # More structured
    'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',  # NEW
    'github_pat': r'ghp_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
    'github_fine_grained_pat': r'github_pat_[0-9a-zA-Z_]{82}',  # NEW - Fine-grained PAT
    'github_oauth': r'gho_[0-9a-zA-Z]{36}',  # GitHub OAuth token
    'gitlab_token': r'glpat-[0-9a-zA-Z\-]{20}',
    'npm_token': r'npm_[a-zA-Z0-9\-\_]{36}',
    'sendgrid_api_key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',  # NEW - SendGrid
    'square_access_token': r'sq0atp-[0-9A-Za-z\-_]{22}',  # NEW - Square payment
    'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}',  # NEW - Square OAuth
    'pypi_upload_token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}',  # NEW - PyPI
    
    # LLM API Keys
    'openai_api_key': r'sk-(?:proj-)?[a-zA-Z0-9]{20,}',
    'anthropic_api_key': r'sk-ant-[a-zA-Z0-9\-_]{95,}',
    'gemini_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'huggingface_token': r'hf_[a-zA-Z0-9]{32,}',
    'cohere_api_key': r'(?i)cohere[_-]?(?:api[_-]?key|key)[=: ]*[\'\"]?([a-zA-Z0-9]{40})[\'\"]?',
    'openrouter_api_key': r'sk-or-v1-[a-zA-Z0-9]{64,}',
    'replicate_api_key': r'r8_[a-zA-Z0-9]{40,}',
    'together_api_key': r'(?i)together[_-]?(?:api[_-]?)?key[=: ]*[\'\"]?([a-zA-Z0-9]{64})[\'\"]?',
    'perplexity_api_key': r'pplx-[a-zA-Z0-9]{40,}',
    'mistral_api_key': r'(?i)mistral[_-]?(?:api[_-]?)?key[=: ]*[\'\"]?([a-zA-Z0-9]{32})[\'\"]?',
    'ai21_api_key': r'(?i)ai21[_-]?(?:api[_-]?)?key[=: ]*[\'\"]?([a-zA-Z0-9]{32,})[\'\"]?',
    'anyscale_api_key': r'esecret_[a-zA-Z0-9]{40,}',
    'deepinfra_api_key': r'(?i)deepinfra[_-]?(?:api[_-]?)?key[=: ]*[\'\"]?([a-zA-Z0-9]{40,})[\'\"]?',
    'groq_api_key': r'gsk_[a-zA-Z0-9]{52}',
    'fireworks_api_key': r'(?i)fireworks[_-]?(?:api[_-]?)?key[=: ]*[\'\"]?([a-zA-Z0-9]{40,})[\'\"]?',
    
    # Database Credentials
    'mongo_uri': r'mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\-\.]+/\w+',
    'postgres_uri': r'postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-\.]+:[0-9]+/\w+',
    'mysql_uri': r'mysql(?:2)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-\.]+:[0-9]+/\w+',
    'redis_uri': r'redis(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-\.]+:[0-9]+/\w+',
    'sql_connection_string': r'sql(?:server)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-\.]+:[0-9]+/\w+',
    
    # Authentication
    'basic_auth': r'basic[\s=:]+([a-zA-Z0-9+/=]+)',
    'oauth_token': r'[0-9]+-[0-9A-Za-z_]{40}',
    'session_token': r'session[_-]?token[=: ]*[\'\"]?([a-f0-9]{64})[\'\"]?',
    'session_id': r'session[_-]?id[=: ]*[\'\"]?([a-f0-9]{32,})[\'\"]?',
    'csrf_token': r'csrf[_-]?token[=: ]*[\'\"]?([a-f0-9]{16,})[\'\"]?',
    
    # Sensitive URLs
    'webhook_url': r'https?://[^\s\'\"]+webhook[^\s\'\"]+',
    'callback_url': r'https?://[^\s\'\"]+callback[^\s\'\"]*',
    'redirect_uri': r'redirect[_-]?uri[=: ]*[\'\"]?(https?://[^\s\'\"]+)[\'\"]?',
    
    # Sensitive Headers and Config
    'auth_header': r'(?i)(?:authorization|proxy[_-]?authorization|X[_-]?API[_-]?Key|X[_-]?API[_-]?Token)[=: ]*[\'\"]?([a-zA-Z0-9_\-\s\.]+)[\'\"]?',
    'http_basic_auth': r'(?i)(?:https?://)([a-zA-Z0-9_\-]+):([^@\s]+)@',
    'cookie_header': r'(?i)(?:set[_-]?cookie|cookie)[=: ]*[\'\"]?([a-zA-Z0-9%_\-\s\.=]{20,})[\'\"]?',
    
    # Sensitive Parameters (more specific to avoid CSS/HTML false positives)
    'password_param': r'(?i)(?:^|[^a-zA-Z-])(?:password|pwd|pass)(?:[_-]?(?:field|input|value|data))?[=: ]+[\'\"]?([^\s\'\"\[\]\.]+)[\'\"]?',
    'token_param': r'(?i)(?:^|[^a-zA-Z-])(?:token|auth[_-]?token|access[_-]?token|refresh[_-]?token)[=: ]+[\'\"]?([a-zA-Z0-9_\-]{20,})[\'\"]?',
    'encrypted_credentials': r'(?i)(?:encrypt|decrypt|decryptString|atob|btoa|CryptoJS\.AES\.decrypt|CryptoJS\.AES\.encrypt|CryptoJS\.enc\.Utf8\.stringify).*?[\'\"]([a-zA-Z0-9+/=]{20,})[\'\"]',
    'id_param': r'(?i)(?:^|[^a-zA-Z-])(?:user[_-]?id|client[_-]?id|app[_-]?id)[=: ]+[\'\"]?([0-9]{10,})[\'\"]?',
    'email_param': r'(?i)(?:email|e[_-]??mail|username|user[_-]?name|login)[=: ]*[\'\"]?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\'\"]?',
    
    # File Paths
    'private_key': r'-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY[\s\S]*?-----END (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----',
    'ssh_private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'ssh_public_key': r'ssh-(rsa|dss|ed25519) [A-Za-z0-9+/]+[=]{0,2}( [^@]+@[^ ]+)?',
    
    # Credit Cards
    'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
    'credit_card_expiry': r'\b(0[1-9]|1[0-2])/([0-9]{2})\b',
    'credit_card_cvv': r'\b[0-9]{3,4}\b',
    
    # IP Addresses
    'ip_address': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'private_ip': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|localhost)\b',
    
    # Other Sensitive Data
    'ssn': r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',
    'phone_number': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
    'date_of_birth': r'\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12][0-9]|3[01])[-/.](19|20)\d{2}\b',
}

# Enhance with imported patterns from GitLeaks
try:
    SECRET_PATTERNS = get_enhanced_patterns(
        custom_patterns=CUSTOM_SECRET_PATTERNS,
        use_cache=True,  # Cache patterns for 24 hours
        include_secrets_db=False  # Use GitLeaks patterns only (160+ patterns)
    )
    logger.info(f"Successfully loaded {len(SECRET_PATTERNS)} detection patterns (custom + GitLeaks)")
except Exception as e:
    logger.warning(f"Failed to import GitLeaks patterns, using custom patterns only: {e}")
    SECRET_PATTERNS = CUSTOM_SECRET_PATTERNS
    logger.info(f"Using {len(SECRET_PATTERNS)} custom detection patterns")

# Compiled regex patterns for better performance
COMPILED_PATTERNS = {}
for name, pattern in SECRET_PATTERNS.items():
    try:
        COMPILED_PATTERNS[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except (re.error, Exception) as e:
        logger.warning(f"Skipping invalid pattern '{name}': {e}")

logger.info(f"Successfully compiled {len(COMPILED_PATTERNS)}/{len(SECRET_PATTERNS)} patterns")

# Known false positives to filter out
FALSE_POSITIVES = [
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',  # UUIDs
    r'^[0-9a-f]{32}$',  # MD5 hashes
    r'^[a-f0-9]{64}$',  # SHA-256 hashes
    r'^[a-f0-9]{128}$',  # SHA-512 hashes
    r'^[0-9a-f]{40}$',  # Git commit hashes
    r'^[0-9a-f]{7}$',  # Short git commit hashes
    r'^[0-9a-f]{5,8}$',  # Short hashes
    r'^[0-9a-f]{16}$',  # 16-byte hex
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # UUID with hyphens
    r'^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$',  # UUID v4
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',  # UUID v4 with hyphens
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[0-9a-f]{6}$',  # UUID with suffix
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12},[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',  # Multiple UUIDs
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?:,[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})*$',  # Comma-separated UUIDs
    r'^[0-9a-f]{32}$',  # MD5 hash
    r'^[a-f0-9]{64}$',  # SHA-256 hash
    r'^[a-f0-9]{128}$',  # SHA-512 hash
    r'^[0-9a-f]{40}$',  # Git commit hash
    r'^[0-9a-f]{7}$',  # Short git commit hash
    r'^[0-9a-f]{5,8}$',  # Short hash
    r'^[0-9a-f]{16}$',  # 16-byte hex
]

# Compile false positive patterns
COMPILED_FALSE_POSITIVES = [re.compile(pattern, re.IGNORECASE) for pattern in FALSE_POSITIVES]

# Known test patterns to filter out
TEST_PATTERNS = [
    r'test',
    r'example',
    r'sample',
    r'demo',
    r'fake',
    r'dummy',
    r'temp',
    r'temporary',
    r'placeholder',
    r'changeme',
    r'password',
    r'1234',
    r'123456',
    r'qwerty',
    r'admin',
    r'root',
    r'user',
    r'guest',
    r'default',
    r'secret',
    r'private',
    r'key',
    r'token',
    r'api',
    r'endpoint',
    r'url',
    r'localhost',
    r'127.0.0.1',
    r'0.0.0.0',
    r'::1',
    r'0000',
    r'1111',
    r'2222',
    r'3333',
    r'4444',
    r'5555',
    r'6666',
    r'7777',
    r'8888',
    r'9999',
    r'00000',
    r'11111',
    r'22222',
    r'33333',
    r'44444',
    r'55555',
    r'66666',
    r'77777',
    r'88888',
    r'99999',
    r'000000',
    r'111111',
    r'222222',
    r'333333',
    r'444444',
    r'555555',
    r'666666',
    r'777777',
    r'888888',
    r'999999',
    r'0000000',
    r'1111111',
    r'2222222',
    r'3333333',
    r'4444444',
    r'5555555',
    r'6666666',
    r'7777777',
    r'8888888',
    r'9999999',
    r'00000000',
    r'11111111',
    r'22222222',
    r'33333333',
    r'44444444',
    r'55555555',
    r'66666666',
    r'77777777',
    r'88888888',
    r'99999999',
]

# Compile test patterns
COMPILED_TEST_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in TEST_PATTERNS]

# Context for findings
FINDING_CONTEXT = {
    'api_key': 'API key found in request or response',
    'jwt_token': 'JWT token found in request or response',
    'bearer_token': 'Bearer token found in request or response',
    'oauth_token': 'OAuth token found in request or response',
    'aws_key': 'AWS access key ID found in request or response',
    'aws_secret': 'AWS secret access key found in request or response',
    'aws_account_id': 'AWS account ID found in request or response',
    'google_api_key': 'Google API key found in request or response',
    'google_oauth': 'Google OAuth token found in request or response',
    'google_service_account': 'Google Cloud service account credentials found in request or response',
    'google_vertex_api_key': 'Google Vertex AI API key found in request or response',
    'firebase': 'Firebase API key found in request or response',
    'heroku_api_key': 'Heroku API key found in request or response',
    'mailgun_api_key': 'Mailgun API key found in request or response',
    'mailchimp_api_key': 'Mailchimp API key found in request or response',
    'twilio_api_key': 'Twilio API key found in request or response',
    'stripe_key': 'Stripe API key found in request or response',
    'stripe_restricted_key': 'Stripe restricted key found in request or response',
    'slack_token': 'Slack token found in request or response',
    'slack_webhook': 'Slack webhook URL found in request or response',
    'github_pat': 'GitHub Personal Access Token found in request or response',
    'github_fine_grained_pat': 'GitHub Fine-Grained Personal Access Token found in request or response',
    'github_oauth': 'GitHub OAuth token found in request or response',
    'gitlab_token': 'GitLab token found in request or response',
    'npm_token': 'npm token found in request or response',
    'sendgrid_api_key': 'SendGrid API key found in request or response',
    'square_access_token': 'Square access token found in request or response',
    'square_oauth_secret': 'Square OAuth secret found in request or response',
    'pypi_upload_token': 'PyPI upload token found in request or response',
    'openai_api_key': 'OpenAI API key found in request or response',
    'anthropic_api_key': 'Anthropic (Claude) API key found in request or response',
    'gemini_api_key': 'Google Gemini API key found in request or response',
    'huggingface_token': 'Hugging Face API token found in request or response',
    'cohere_api_key': 'Cohere API key found in request or response',
    'openrouter_api_key': 'OpenRouter API key found in request or response',
    'replicate_api_key': 'Replicate API key found in request or response',
    'together_api_key': 'Together AI API key found in request or response',
    'perplexity_api_key': 'Perplexity AI API key found in request or response',
    'mistral_api_key': 'Mistral AI API key found in request or response',
    'ai21_api_key': 'AI21 Labs API key found in request or response',
    'anyscale_api_key': 'Anyscale API key found in request or response',
    'deepinfra_api_key': 'DeepInfra API key found in request or response',
    'groq_api_key': 'Groq API key found in request or response',
    'fireworks_api_key': 'Fireworks AI API key found in request or response',
    'mongo_uri': 'MongoDB connection string found in request or response',
    'postgres_uri': 'PostgreSQL connection string found in request or response',
    'mysql_uri': 'MySQL connection string found in request or response',
    'redis_uri': 'Redis connection string found in request or response',
    'sql_connection_string': 'SQL connection string found in request or response',
    'basic_auth': 'Basic authentication credentials found in request or response',
    'session_token': 'Session token found in request or response',
    'session_id': 'Session ID found in request or response',
    'csrf_token': 'CSRF token found in request or response',
    'webhook_url': 'Webhook URL found in request or response',
    'callback_url': 'Callback URL found in request or response',
    'redirect_uri': 'Redirect URI found in request or response',
    'auth_header': 'Authorization header found in request or response',
    'cookie_header': 'Cookie header found in request or response',
    'password_param': 'Password parameter found in request or response',
    'token_param': 'Token parameter found in request or response',
    'id_param': 'ID parameter found in request or response',
    'email_param': 'Email parameter found in request or response',
    'private_key': 'Private key found in request or response',
    'ssh_private_key': 'SSH private key found in request or response',
    'ssh_public_key': 'SSH public key found in request or response',
    'credit_card': 'Credit card number found in request or response',
    'credit_card_expiry': 'Credit card expiry date found in request or response',
    'credit_card_cvv': 'Credit card CVV found in request or response',
    'ip_address': 'IP address found in request or response',
    'private_ip': 'Private IP address found in request or response',
    'ssn': 'Social Security Number found in request or response',
    'phone_number': 'Phone number found in request or response',
    'date_of_birth': 'Date of birth found in request or response',
}

# Severity levels for findings
SEVERITY_LEVELS = {
    'high': [
        'aws_key', 'aws_secret', 'google_api_key', 'google_service_account', 'google_vertex_api_key',
        'firebase', 'heroku_api_key', 'mailgun_api_key', 'mailchimp_api_key',
        'twilio_api_key', 'stripe_key', 'stripe_restricted_key', 'slack_token', 'slack_webhook',
        'github_pat', 'github_fine_grained_pat', 'github_oauth', 'gitlab_token', 'npm_token', 
        'sendgrid_api_key', 'square_access_token', 'square_oauth_secret', 'pypi_upload_token',
        'openai_api_key', 'anthropic_api_key', 'gemini_api_key', 'huggingface_token', 'cohere_api_key',
        'openrouter_api_key', 'replicate_api_key', 'together_api_key', 'perplexity_api_key',
        'mistral_api_key', 'ai21_api_key', 'anyscale_api_key', 'deepinfra_api_key', 'groq_api_key', 'fireworks_api_key',
        'private_key', 'ssh_private_key', 'credit_card', 'credit_card_cvv', 'ssn'
    ],
    'medium': [
        'api_key', 'jwt_token', 'bearer_token', 'oauth_token', 'aws_account_id',
        'google_oauth', 'mongo_uri', 'postgres_uri', 'mysql_uri', 'redis_uri',
        'sql_connection_string', 'basic_auth', 'session_token', 'webhook_url',
        'callback_url', 'redirect_uri', 'auth_header', 'ssh_public_key',
        'credit_card_expiry', 'private_ip'
    ],
    'low': [
        'session_id', 'csrf_token', 'cookie_header', 'password_param', 'token_param',
        'id_param', 'email_param', 'ip_address', 'phone_number', 'date_of_birth'
    ]
}

def get_severity(finding_type: str) -> str:
    """Get the severity level for a finding type."""
    for level, types in SEVERITY_LEVELS.items():
        if finding_type in types:
            return level
    return 'info'

def is_false_positive(value: str) -> bool:
    """Check if a value is a false positive."""
    if not value or not isinstance(value, str):
        return True
        
    value = value.strip()
    
    # Common false positives
    false_positives = [
        'api_key', 'your_api_key', 'example.com', 'test', 'password',
        'secret_key', 'change_this', 'your_password', 'your_secret_key',
        '00000000-0000-0000-0000-000000000000', '1234567890', '0123456789',
        'client_id', 'client_secret', 'access_token', 'refresh_token',
        'bearer', 'basic', 'token', 'key', 'secret', 'undefined', 'null',
        'true', 'false', 'yes', 'no', 'example', 'demo', 'dummy', 'test',
        'development', 'staging', 'production', 'localhost', '127.0.0.1'
    ]
    
    # Check if value is in false positives list (case insensitive)
    value_lower = value.lower()
    if any(fp.lower() in value_lower for fp in false_positives):
        return True
        
    # Check if value is too short or too long to be a real secret
    if len(value) < 10 or len(value) > 1000:
        return True
        
    # Check if value is just a number or simple string
    if value.isdigit() or value.isalpha() or value.isalnum():
        if len(set(value)) < 5:  # Too few unique characters
            return True
    
    # Check for CSS classes, selectors, and Angular attributes
    css_patterns = [
        r'^\.[\w-]+$',  # CSS class selectors like .maplibregl-ctrl-icon
        r'^\[_ng[\w-]+\]$',  # Angular attributes like [_ngcontent-ng-c3505523955]
        r'^[\w-]+\[_ng[\w-]+\]$',  # Combined like .cp-onboarding[_ngcontent-ng-c3505523955]
        r'^\{[\w\s,]+\}$',  # CSS property groups
        r'^[\w-]+:[\w-]+$',  # CSS pseudo-classes
        r'^@[\w-]+',  # CSS at-rules
        r'^\d+px$',  # Pixel values
        r'^\d+rem$',  # Rem values
        r'^#[0-9a-fA-F]{3,6}$',  # Hex colors
        r'^rgb\(',  # RGB colors
        r'^rgba\(',  # RGBA colors
    ]
    
    for pattern in css_patterns:
        if re.match(pattern, value):
            return True
    
    # Check if it looks like CSS content (contains common CSS keywords)
    css_keywords = ['cursor:', 'background:', 'margin:', 'padding:', 'font-', 'color:', 'width:', 'height:']
    if any(keyword in value_lower for keyword in css_keywords):
        return True
    
    # Check for IP addresses that look fake or are in reserved ranges
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, value):
        parts = value.split('.')
        # Check for obviously fake IPs (like 27.99.097.11 with leading zeros)
        if any(part.startswith('0') and len(part) > 1 for part in parts):
            return True
        # Check for reserved/private IP ranges
        first = int(parts[0])
        if first in [0, 10, 127, 169, 172, 192, 224, 240, 255]:
            return True
    
    # Check for common placeholder patterns
    placeholder_patterns = [
        r'\b(?:replace|enter|your|add|insert|set|use)[_\- ]*(?:your|the|this|a)?[_\- ]*(?:api[_-]?key|key|secret|token|password|pwd|credential|id)\b',
        r'\b(?:YOUR[_-]?)?(API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD|PWD|CREDENTIALS?|ID)\b',
        r'\b(?:test|dev|staging|prod|production)[_\-](?:key|secret|token|password|pwd|credential|id)\b',
        r'\b(?:example|sample|dummy|placeholder)[_\-](?:key|secret|token|password|pwd|credential|id)\b',
    ]
    
    for pattern in placeholder_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    
    # Check if it's a short app key (like BO-AAB-DXD) - likely a public identifier
    if re.match(r'^[A-Z]{2,3}-[A-Z]{3}-[A-Z]{3}$', value):
        return True
    
    # Filter out JavaScript built-in functions and common Web APIs
    js_builtins = [
        'encodeuricomponent', 'decodeuricomponent', 'encodeuri', 'decodeuri',
        'btoa', 'atob', 'settimeout', 'setinterval', 'clearinterval', 'cleartimeout',
        'getelementbyid', 'queryselector', 'queryselectorall', 'addeventlistener',
        'removeeventlistener', 'preventdefault', 'stoppropagation', 'stopimmediatepropagation',
        'json.parse', 'json.stringify', 'object.keys', 'object.values', 'object.entries',
        'array.from', 'array.isarray', 'array.prototype', 'string.prototype',
        'math.random', 'math.floor', 'math.ceil', 'math.round', 'math.max', 'math.min',
        'date.now', 'date.parse', 'date.prototype', 'localstorage', 'sessionstorage',
        'fetch', 'xmlhttprequest', 'promise', 'async', 'await', 'setcookie', 'getcookie',
        'disablecookie', 'enablecookie', 'setcookie', 'deletecookie', 'cookievalue',
        'document.cookie', 'window.location', 'window.history', 'window.localstorage',
        'console.log', 'console.error', 'console.warn', 'console.info', 'console.debug',
    ]
    
    # Check if it's a JavaScript built-in function or common API
    value_lower_no_underscores = value_lower.replace('_', '').replace('-', '')
    if any(builtin in value_lower_no_underscores for builtin in js_builtins):
        return True
    
    # Filter out common variable/function names that contain credential-related words but aren't credentials
    # These are typically camelCase or PascalCase variable names
    variable_name_patterns = [
        r'^[a-z][a-zA-Z0-9]*[Pp]refix$',  # e.g., fidesPrefix, apiPrefix
        r'^[a-z][a-zA-Z0-9]*[Cc]ookie$',  # e.g., disableCookie, enableCookie
        r'^[a-z][a-zA-Z0-9]*[Kk]ey$',     # e.g., getKey, setKey (but not actual keys)
        r'^[a-z][a-zA-Z0-9]*[Tt]oken$',   # e.g., getToken, setToken (but not actual tokens)
        r'^[a-z][a-zA-Z0-9]*[Pp]assword$', # e.g., validatePassword (but not actual passwords)
        r'^[a-z][a-zA-Z0-9]*[Ss]ecret$',   # e.g., getSecret (but not actual secrets)
    ]
    
    # Only filter if it's a short variable name (actual credentials are usually longer)
    if len(value) < 30:
        for pattern in variable_name_patterns:
            if re.match(pattern, value):
                return True
    
    # Filter out function calls - if it looks like a function name (contains parentheses nearby in context)
    # We'll check this in the context-aware filtering
    
    # Check for OAuth token patterns that are likely false positives
    # Real OAuth tokens typically have more structure and appear in specific contexts
    oauth_pattern = r'^[0-9]+-[0-9A-Za-z_]{40}$'
    if re.match(oauth_pattern, value):
        # Check if it looks like a variable name or identifier rather than a token
        # Real OAuth tokens are usually longer or have specific prefixes
        # Single digit prefix with exactly 40 chars is often a false positive
        if re.match(r'^[0-9]{1,2}-[0-9A-Za-z_]{40}$', value):
            # Check if it appears to be a random identifier (high entropy but not a real token)
            # Real OAuth tokens from major providers have specific formats:
            # - Google: ya29.xxxxx
            # - Twitter: different format
            # - Generic OAuth 2.0: usually longer or have specific prefixes
            # Values matching this pattern without context are often false positives
            return True
            
    return False

def analyze_javascript(content: str, source: str) -> List[Dict[str, Any]]:
    """Analyze JavaScript/TypeScript code for security issues."""
    findings = []
    
    # Detect client-side decryption patterns
    decryption_patterns = [
        # CryptoJS patterns
        (r'CryptoJS\.AES\.decrypt\([^,]+,\s*["\']([^"\']{16,})["\']', 'crypto_js_aes_decrypt'),
        (r'CryptoJS\.AES\.encrypt\([^,]+,\s*["\']([^"\']{16,})["\']', 'crypto_js_aes_encrypt'),
        
        # Web Crypto API patterns
        (r'crypto\.subtle\.(?:importKey|decrypt|encrypt|sign|verify|digest|generateKey|deriveKey|deriveBits|wrapKey|unwrapKey)\s*\([^)]+["\']([^"\']{16,})["\']', 'web_crypto_api_key'),
        
        # Common encryption/decryption function patterns
        (r'(?:decrypt|decryptString|decode|unlock|getSecret|getKey|getToken)\([^)]*["\']([^"\']{16,})["\']', 'custom_decryption_function'),
        
        # Hardcoded encryption keys
        (r'(?:key|secret|token|password|pwd|pass)[\s=:]+["\']([^"\']{16,})["\']', 'hardcoded_secret'),
        
        # Base64 encoded secrets
        (r'[a-zA-Z0-9+/=]{20,}', 'potential_base64_secret')
    ]
    
    for pattern, issue_type in decryption_patterns:
        for match in re.finditer(pattern, content, re.DOTALL):
            value = match.group(1) if len(match.groups()) > 0 else match.group(0)
            if is_false_positive(value):
                continue
                
            # Get line number and context
            line_num = content.count('\n', 0, match.start()) + 1
            lines = content.splitlines()
            start_line = max(1, line_num - 2)
            end_line = min(len(lines), line_num + 2)
            context = '\n'.join(f"{i}: {line}" for i, line in enumerate(lines[start_line-1:end_line], start_line))
            
            findings.append({
                'type': issue_type,
                'value': value,
                'severity': 'high',
                'context': f"Potential {issue_type.replace('_', ' ')} found in {source}",
                'source': source,
                'line': line_num,
                'context_lines': context,
                'in_comment': False,
                'recommendation': 'Move sensitive operations to server-side. Never perform encryption/decryption with hardcoded keys in client-side code.'
            })
    
    return findings

def find_credentials_in_comments(content: str, source: str) -> List[Dict[str, Any]]:
    """Find credentials in code comments."""
    findings = []
    
    # Patterns to detect credentials in comments
    comment_patterns = [
        (r'//\s*(username|password|key|secret|token|api[_-]?key)[\s=:]+([^\s\n]+)', 'single_line_comment_credential'),
        (r'/\*[^*]*?(username|password|key|secret|token|api[_-]?key)[\s=:]+([^\s\*]+)', 'multi_line_comment_credential'),
        (r'#\s*(username|password|key|secret|token|api[_-]?key)[\s=:]+([^\s\n]+)', 'comment_credential')
    ]
    
    for pattern, issue_type in comment_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            key = match.group(1).lower()
            value = match.group(2).strip()
            
            if is_false_positive(value):
                continue
                
            # Get line number and context
            line_num = content.count('\n', 0, match.start()) + 1
            lines = content.splitlines()
            start_line = max(1, line_num - 2)
            end_line = min(len(lines), line_num + 2)
            context = '\n'.join(f"{i}: {line}" for i, line in enumerate(lines[start_line-1:end_line], start_line))
            
            findings.append({
                'type': issue_type,
                'value': f"{key}={value}",
                'severity': 'critical',
                'context': f"Potential hardcoded credential in comment at line {line_num} in {source}",
                'source': source,
                'line': line_num,
                'context_lines': context,
                'in_comment': True,
                'recommendation': 'Remove hardcoded credentials from source code. Use environment variables or a secure secrets management solution.'
            })
    
    return findings

def analyze_content(content: str, source: str = '') -> List[Dict[str, Any]]:
    """
    Analyze content for potential secrets and security issues.
    
    This function analyzes the provided content for various types of sensitive
    information like API keys, tokens, credentials, etc. It uses a combination
    of regex patterns and heuristics to identify potential security issues.
    
    Args:
        content: The content to analyze (source code, configuration, etc.)
        source: Source identifier (URL, file path, etc.) used for reporting
        
    Returns:
        List of dictionaries, each representing a finding with details about
        the detected security issue including type, severity, and remediation
        recommendations.
    """
    findings = []
    
    # If content is not a string, convert it to string
    if not isinstance(content, str):
        try:
            content = str(content)
        except Exception as e:
            logger.warning(f"Failed to convert content to string: {e}")
            return findings
    
    # Check for potential secrets using regex patterns
    for name, pattern in COMPILED_PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(1) if len(match.groups()) > 0 else match.group(0)
            
            # Skip if it's a false positive
            if is_false_positive(value):
                continue
            
            # Additional context-aware filtering for OAuth tokens
            if name == 'oauth_token':
                # Check the context around the match to see if it's actually being used as a credential
                match_start = match.start()
                match_end = match.end()
                context_start = max(0, match_start - 50)
                context_end = min(len(content), match_end + 50)
                context = content[context_start:context_end].lower()
                
                # If it doesn't appear near credential-related keywords, it's likely a false positive
                credential_keywords = ['token', 'oauth', 'authorization', 'bearer', 'access', 'auth', 'credential', 'api']
                if not any(keyword in context for keyword in credential_keywords):
                    # Also check if it appears to be part of a variable name or identifier
                    # (e.g., if it's surrounded by alphanumeric characters on both sides)
                    char_before = content[match_start - 1] if match_start > 0 else ' '
                    char_after = content[match_end] if match_end < len(content) else ' '
                    if (char_before.isalnum() or char_before == '_') and (char_after.isalnum() or char_after == '_'):
                        # It's part of a larger identifier, likely a false positive
                        continue
            
            # Context-aware filtering for hardcoded_creds
            if name == 'hardcoded_creds':
                match_start = match.start()
                match_end = match.end()
                context_start = max(0, match_start - 100)
                context_end = min(len(content), match_end + 50)
                context = content[context_start:context_end]
                
                # Check if it's a variable name assignment (like "var fidesPrefix = ...")
                # Variable names are usually followed by = or :, but actual credentials are usually string values
                value_match = match.group(1) if len(match.groups()) > 0 else match.group(0)
                
                # Check if the value looks like a variable name (camelCase starting with lowercase)
                if re.match(r'^[a-z][a-zA-Z0-9]*$', value_match) and len(value_match) < 25:
                    # Check if it's preceded by a variable declaration pattern
                    before_match = content[max(0, match_start - 20):match_start]
                    if re.search(r'(?:var|let|const|function|class|this\.|\.|\[)[\s]*$', before_match):
                        continue
                
                # Check if it's a function call (like encodeURIComponent, disableCookie)
                if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', context[max(0, match_start - context_start - 30):]):
                    continue
                
                # Check if it's a property access (like .key, .token, etc.)
                if re.search(r'\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*[:=]', context[max(0, match_start - context_start - 20):]):
                    continue
            
            # Context-aware filtering for cookie_header
            if name == 'cookie_header':
                match_start = match.start()
                match_end = match.end()
                value_match = match.group(1) if len(match.groups()) > 0 else match.group(0)
                
                # Filter out JavaScript functions
                if value_match in ['encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI', 
                                 'disableCookie', 'enableCookie', 'setCookie', 'getCookie', 'deleteCookie']:
                    continue
                
                # Check if it's a function call pattern
                context_start = max(0, match_start - 30)
                context_before = content[context_start:match_start]
                if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*\([\s]*$', context_before):
                    continue
                
                # Cookie values should be longer (actual cookie values, not function names)
                if len(value_match) < 15:
                    continue
            
            # Get line number and surrounding context
            lines = content.splitlines()
            line_num = content.count('\n', 0, match.start()) + 1
            start_line = max(1, line_num - 2)
            end_line = min(len(lines), line_num + 2)
            
            # Get the full line where the match occurred
            line_content = lines[line_num - 1] if line_num <= len(lines) else ''
            
            # Truncate very long lines (like minified CSS/JS) for better display
            max_line_length = 200
            context_lines_list = []
            for i, line in enumerate(lines[start_line-1:end_line], start_line):
                if len(line) > max_line_length:
                    # Find the position of the match in this line
                    if i == line_num:
                        # This is the line with the match - show context around the match
                        match_pos = match.start() - sum(len(l) + 1 for l in lines[:line_num-1])
                        snippet_start = max(0, match_pos - 50)
                        snippet_end = min(len(line), match_pos + 100)
                        snippet = line[snippet_start:snippet_end]
                        if snippet_start > 0:
                            snippet = '...' + snippet
                        if snippet_end < len(line):
                            snippet = snippet + '...'
                        context_lines_list.append(f"{i}: {snippet}")
                    else:
                        # Other lines - just truncate
                        context_lines_list.append(f"{i}: {line[:max_line_length]}...")
                else:
                    context_lines_list.append(f"{i}: {line}")
            
            context = '\n'.join(context_lines_list)
            
            # Check if this is in a comment
            is_comment = False
            if source.endswith(('.js', '.jsx', '.ts', '.tsx')):
                # For JavaScript/TypeScript, check for // or /* */ comments
                line_before = line_content[:match.start() - (match.start(1) if len(match.groups()) > 0 else 0)]
                is_comment = '//' in line_before or '/*' in line_before
            elif source.endswith(('.py',)):
                # For Python, check for # comments
                is_comment = '#' in line_content[:match.start() - (match.start(1) if len(match.groups()) > 0 else 0)]
            
            # Get severity based on type and context
            severity = get_severity(name)
            
            # Get recommendation based on finding type
            recommendation = get_recommendation(name, value, source)
            
            # Create finding
            finding = {
                'type': name,
                'value': value,
                'severity': 'critical' if is_comment and any(k in name.lower() for k in ['key', 'secret', 'token', 'password']) else get_severity(name),
                'context': f"Potential {name.replace('_', ' ')} found in {source}",
                'source': source,
                'line': line_num,
                'context_lines': context,
                'in_comment': is_comment,
                'recommendation': recommendation
            }
            findings.append(finding)
    
    # Run additional analyzers based on file type
    if source.endswith(('.js', '.jsx', '.ts', '.tsx', '.html')):
        js_findings = analyze_javascript(content, source)
        findings.extend(js_findings)
    
    if any(ext in source.lower() for ext in ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.php']):
        comment_creds = find_credentials_in_comments(content, source)
        findings.extend(comment_creds)
    
    # Deduplicate findings - merge duplicates based on value, source, and line
    # Priority: more specific pattern names, then higher severity
    value_location_map = {}  # Maps (value, source, line) to best finding
    
    # Patterns that are essentially the same (keep the more specific one)
    pattern_priority = {
        'google_api_key': 1,  # General Google API key
        'oauth_token': 1,
    }
    
    for finding in findings:
        value = finding.get('value', '')
        source = finding.get('source', '')
        line = finding.get('line', 0)
        finding_type = finding.get('type', '')
        
        # Create key based on value and location (not type)
        key = (value, source, line)
        
        if key not in value_location_map:
            value_location_map[key] = finding
        else:
            # We have a duplicate - keep the better one
            existing = value_location_map[key]
            existing_type = existing.get('type', '')
            existing_severity = existing.get('severity', 'low')
            new_severity = finding.get('severity', 'low')
            
            # Priority: more specific pattern > higher severity > existing one
            existing_priority = pattern_priority.get(existing_type, 999)
            new_priority = pattern_priority.get(finding_type, 999)
            
            should_replace = False
            
            # If new pattern is more specific (lower priority number), use it
            if new_priority < existing_priority:
                should_replace = True
            # If same priority, prefer higher severity
            elif new_priority == existing_priority:
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                if severity_order.get(new_severity, 0) > severity_order.get(existing_severity, 0):
                    should_replace = True
            
            if should_replace:
                value_location_map[key] = finding
    
    return list(value_location_map.values())

def get_recommendation(finding_type: str, value: str, source: str) -> str:
    """Get a recommendation for fixing a finding with validation instructions."""
    recommendations = {
        'aws_key': 'CRITICAL: Rotate this AWS access key immediately. Test validity: aws sts get-caller-identity --no-cli-pager. Use IAM roles or AWS Secrets Manager instead of hardcoding.',
        'aws_secret': 'CRITICAL: Rotate this AWS secret key immediately. Never commit AWS credentials to code. Use IAM roles or AWS Secrets Manager.',
        'google_api_key': 'CRITICAL: Rotate this Google API key immediately. Test: curl "https://www.googleapis.com/youtube/v3/activities?key=KEY_HERE". Restrict key usage in Google Cloud Console and use environment variables.',
        'google_service_account': 'CRITICAL: Google Cloud service account credentials exposed. This provides full access to GCP resources. Rotate immediately in IAM & Admin console, revoke compromised key, and audit all GCP resource access logs.',
        'google_vertex_api_key': 'CRITICAL: Rotate this Google Vertex AI API key immediately. Test: curl "https://generativelanguage.googleapis.com/v1/models?key=KEY". This can incur significant AI/ML charges. Restrict in GCP Console and use environment variables.',
        'stripe_key': 'CRITICAL: Rotate immediately. Test validity: curl https://api.stripe.com/v1/charges -u KEY:. Note: sk_live_ keys expose production data, pk_ keys can expose rate limits. Use environment variables and restrict key permissions.',
        'slack_token': 'CRITICAL: Revoke and rotate. Test: curl -X POST "https://slack.com/api/auth.test?token=TOKEN&pretty=1". Regenerate in Slack App settings.',
        'slack_webhook': 'HIGH: Slack webhook URL exposed. Anyone with this URL can post messages to your Slack channel. Regenerate webhook in Slack settings and restrict usage to server-side only.',
        'github_pat': 'CRITICAL: Revoke this GitHub Personal Access Token immediately. Test: curl -H "Authorization: token TOKEN" https://api.github.com/user. Generate new token with minimal required scopes.',
        'github_fine_grained_pat': 'CRITICAL: Revoke this GitHub Fine-Grained PAT immediately. Test: curl -H "Authorization: token TOKEN" https://api.github.com/user. These tokens have specific repository access - regenerate with minimal permissions.',
        'github_oauth': 'CRITICAL: Revoke this GitHub OAuth token. Test: curl -H "Authorization: token TOKEN" https://api.github.com/user. Generate new token with minimal scopes.',
        'sendgrid_api_key': 'CRITICAL: Rotate this SendGrid API key immediately. Test: curl -X GET "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer KEY". This could be used to send emails from your domain. Rotate in SendGrid dashboard.',
        'square_access_token': 'CRITICAL: Rotate this Square access token immediately. Test: curl https://connect.squareup.com/v2/locations -H "Authorization: Bearer TOKEN". This provides access to payment processing. Rotate in Square Developer Dashboard.',
        'square_oauth_secret': 'CRITICAL: Rotate this Square OAuth secret immediately. This is used for OAuth authentication and could compromise your Square integration. Regenerate in Square Developer Dashboard.',
        'pypi_upload_token': 'CRITICAL: Rotate this PyPI upload token immediately. Test: pip install twine && twine upload --repository-url https://test.pypi.org/legacy/ PACKAGE. This could be used to publish malicious packages. Revoke in PyPI account settings.',
        'firebase': 'HIGH: This Firebase API key is exposed. While client-side keys are expected, ensure Firebase Security Rules are properly configured to prevent unauthorized access.',
        'heroku_api_key': 'CRITICAL: Rotate immediately. Test: curl -n https://api.heroku.com/account -H "Authorization: Bearer KEY". Regenerate in Heroku account settings.',
        'mailgun_api_key': 'CRITICAL: Rotate this Mailgun API key. Test: curl --user "api:KEY" https://api.mailgun.net/v3/domains. This could be used to send emails from your domain.',
        'twilio_api_key': 'CRITICAL: Rotate immediately. Test: curl -X GET "https://api.twilio.com/2010-04-01/Accounts.json" -u ACCOUNT_SID:AUTH_TOKEN. Could result in SMS/call charges.',
        'openai_api_key': 'CRITICAL: Rotate this OpenAI API key immediately. Test: curl https://api.openai.com/v1/models -H "Authorization: Bearer KEY". This could incur significant charges. Rotate in OpenAI dashboard and use environment variables.',
        'anthropic_api_key': 'CRITICAL: Rotate this Anthropic (Claude) API key immediately. Test: curl https://api.anthropic.com/v1/messages -H "x-api-key: KEY" -H "anthropic-version: 2023-06-01". Regenerate in Anthropic Console.',
        'gemini_api_key': 'CRITICAL: Rotate this Google Gemini API key immediately. Test: curl "https://generativelanguage.googleapis.com/v1/models?key=KEY". Restrict usage in Google Cloud Console and use environment variables.',
        'huggingface_token': 'HIGH: Rotate this Hugging Face token. Test: curl -H "Authorization: Bearer TOKEN" https://huggingface.co/api/whoami. Could expose private models/datasets. Regenerate in HF settings.',
        'cohere_api_key': 'CRITICAL: Rotate this Cohere API key immediately. Test: curl https://api.cohere.ai/v1/check-api-key -H "Authorization: Bearer KEY". Could incur API charges. Regenerate in Cohere dashboard.',
        'openrouter_api_key': 'CRITICAL: Rotate this OpenRouter API key immediately. Test: curl https://openrouter.ai/api/v1/auth/key -H "Authorization: Bearer KEY". This provides access to multiple LLM providers. Regenerate in OpenRouter dashboard.',
        'replicate_api_key': 'CRITICAL: Rotate this Replicate API key immediately. Test: curl -H "Authorization: Token KEY" https://api.replicate.com/v1/account. Could incur significant model inference charges.',
        'together_api_key': 'CRITICAL: Rotate this Together AI API key immediately. Test: curl https://api.together.xyz/models -H "Authorization: Bearer KEY". Could incur API charges. Regenerate in Together AI settings.',
        'perplexity_api_key': 'CRITICAL: Rotate this Perplexity AI API key immediately. Test: curl https://api.perplexity.ai/chat/completions -H "Authorization: Bearer KEY". Could incur API usage charges.',
        'mistral_api_key': 'CRITICAL: Rotate this Mistral AI API key immediately. Test: curl https://api.mistral.ai/v1/models -H "Authorization: Bearer KEY". Could incur API charges. Regenerate in Mistral console.',
        'ai21_api_key': 'CRITICAL: Rotate this AI21 Labs API key immediately. Test: curl https://api.ai21.com/studio/v1/models -H "Authorization: Bearer KEY". Could incur API charges.',
        'anyscale_api_key': 'CRITICAL: Rotate this Anyscale API key immediately. Test: curl https://api.endpoints.anyscale.com/v1/models -H "Authorization: Bearer KEY". Could incur compute charges.',
        'deepinfra_api_key': 'CRITICAL: Rotate this DeepInfra API key immediately. Test: curl https://api.deepinfra.com/v1/openai/models -H "Authorization: Bearer KEY". Could incur inference charges.',
        'groq_api_key': 'CRITICAL: Rotate this Groq API key immediately. Test: curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer KEY". Could incur API charges. Regenerate in Groq console.',
        'fireworks_api_key': 'CRITICAL: Rotate this Fireworks AI API key immediately. Test: curl https://api.fireworks.ai/inference/v1/models -H "Authorization: Bearer KEY". Could incur inference charges.',
        'jwt_token': 'MEDIUM: JWT token found. Verify it\'s not a long-lived token. Decode at jwt.io to check expiration. Implement short-lived tokens with refresh mechanism.',
        'api_key': 'HIGH: Remove this API key from the code. Store in environment variables or secrets manager. Test validity against the service\'s API documentation.',
        'bearer_token': 'HIGH: Bearer tokens should never be hardcoded. Implement secure token storage and refresh mechanisms.',
        'password_param': 'HIGH: Hardcoded password detected. Remove immediately and use secure password management. Check if this password is used elsewhere.',
        'private_key': 'CRITICAL: Private key exposed. NEVER commit private keys. Rotate immediately, update authorized_keys files, and audit access logs.',
        'ssh_private_key': 'CRITICAL: SSH private key exposed. Rotate immediately, remove from authorized_keys on all servers, and audit SSH access logs.',
        'mongo_uri': 'CRITICAL: MongoDB connection string with credentials exposed. Rotate password, use IP whitelisting, and store credentials in environment variables.',
        'postgres_uri': 'CRITICAL: PostgreSQL connection string exposed. Rotate password immediately, restrict network access, and use environment variables.',
        'mysql_uri': 'CRITICAL: MySQL connection string exposed. Change password, restrict host access, and move credentials to secure configuration.',
        'redis_uri': 'CRITICAL: Redis connection string exposed. Rotate password, enable AUTH, restrict network access, and use environment variables.',
        'webhook_url': 'MEDIUM: Webhook URL exposed. While not always secret, this could allow unauthorized access. Consider adding authentication or rotating the URL.',
        'http_basic_auth': 'HIGH: HTTP Basic Auth credentials in URL. This is insecure. Use OAuth, API keys, or other modern authentication methods.',
        'encrypted_credentials': 'HIGH: Client-side encryption with hardcoded keys is insecure. Move encryption to server-side with proper key management (AWS KMS, Azure Key Vault).',
        'hardcoded_creds': 'HIGH: Hardcoded credentials found. Remove immediately, rotate credentials, and use environment variables or secrets manager.',
        'crypto_js_aes_decrypt': 'HIGH: Client-side decryption is insecure. Move sensitive operations to server-side. Never store encryption keys in client code.',
        'web_crypto_api_key': 'HIGH: Client-side encryption with hardcoded keys detected. This is not secure. Implement server-side encryption with proper key management.',
        'custom_decryption_function': 'HIGH: Client-side decryption function with hardcoded key. Move to server-side or use proper key derivation functions.',
        'potential_base64_secret': 'MEDIUM: Potential base64-encoded secret. Decode and verify. If it\'s a credential, remove and use secure storage.',
        'single_line_comment_credential': 'HIGH: Credential in code comment. Remove from version control history using tools like BFG Repo-Cleaner or git-filter-repo.',
        'multi_line_comment_credential': 'HIGH: Credential in multi-line comment. Remove and ensure it\'s purged from git history.',
        'comment_credential': 'HIGH: Credential found in comment. Comments are stored in version control. Remove and rotate the credential.'
    }
    
    # Default recommendation if specific one not found
    default_rec = 'Review this finding and remove any sensitive information. Consider using environment variables or a secure secrets management solution.'
    
    return recommendations.get(finding_type, default_rec)

class RequestHandler:
    """Handler for HTTP requests and responses."""
    
    def __init__(self):
        self.findings = []
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP request."""
        try:
            # Skip binary data
            if flow.request.raw_content and len(flow.request.raw_content) > 10 * 1024 * 1024:  # 10MB
                return
                
            # Analyze URL
            url = flow.request.pretty_url
            url_findings = analyze_content(url, 'URL')
            self.findings.extend(url_findings)
            
            # Analyze headers
            for name, value in flow.request.headers.items():
                header_str = f"{name}: {value}"
                header_findings = analyze_content(header_str, 'Request Header')
                self.findings.extend(header_findings)
            
            # Analyze query parameters
            if flow.request.query:
                query_str = '&'.join([f"{k}={v}" for k, v in flow.request.query.items()])
                query_findings = analyze_content(query_str, 'Query Parameters')
                self.findings.extend(query_findings)
            
            # Analyze form data
            if flow.request.urlencoded_form:
                form_str = '&'.join([f"{k}={v}" for k, v in flow.request.urlencoded_form.items()])
                form_findings = analyze_content(form_str, 'Form Data')
                self.findings.extend(form_findings)
            
            # Analyze JSON body
            if flow.request.text and 'application/json' in flow.request.headers.get('content-type', '').lower():
                try:
                    json_data = flow.request.json()
                    json_str = json.dumps(json_data)
                    json_findings = analyze_content(json_str, 'JSON Body')
                    self.findings.extend(json_findings)
                except:
                    pass
            
            # Analyze raw body
            if flow.request.text:
                body_findings = analyze_content(flow.request.text, 'Request Body')
                self.findings.extend(body_findings)
                
        except Exception as e:
            logger.error(f"Error processing request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP response."""
        try:
            # Skip binary data
            if flow.response.raw_content and len(flow.response.raw_content) > 10 * 1024 * 1024:  # 10MB
                return
            
            # Analyze response headers
            for name, value in flow.response.headers.items():
                header_str = f"{name}: {value}"
                header_findings = analyze_content(header_str, 'Response Header')
                self.findings.extend(header_findings)
            
            # Analyze response body
            if flow.response.text:
                # Check content type
                content_type = flow.response.headers.get('content-type', '').lower()
                
                # Handle JSON responses
                if 'application/json' in content_type:
                    try:
                        json_data = flow.response.json()
                        json_str = json.dumps(json_data)
                        json_findings = analyze_content(json_str, 'JSON Response')
                        self.findings.extend(json_findings)
                    except:
                        pass
                
                # Handle HTML responses
                elif 'text/html' in content_type:
                    try:
                        soup = BeautifulSoup(flow.response.text, 'html.parser')
                        
                        # Check for sensitive data in script tags (inline JavaScript)
                        for idx, script in enumerate(soup.find_all('script')):
                            if script.string and len(script.string.strip()) > 0:
                                script_findings = analyze_content(script.string, f'Inline JavaScript (Script #{idx+1})')
                                self.findings.extend(script_findings)
                        
                        # Check for sensitive data in data attributes and specific HTML attributes
                        for tag in soup.find_all(attrs={'data-config': True}):
                            config_findings = analyze_content(str(tag.get('data-config', '')), 'HTML Data Attribute')
                            self.findings.extend(config_findings)
                        
                        # Check for sensitive data in meta tags
                        for meta in soup.find_all('meta'):
                            for attr in ['content']:  # Only check content, not name/property
                                if attr in meta.attrs:
                                    content_value = meta[attr]
                                    if len(str(content_value)) > 20:  # Only check substantial content
                                        meta_findings = analyze_content(str(content_value), 'Meta Tag Content')
                                        self.findings.extend(meta_findings)
                    except Exception as e:
                        logger.debug(f"Error parsing HTML: {e}")
                
                # Handle plain text responses (skip binary content)
                elif 'text/' in content_type or 'javascript' in content_type:
                    try:
                        text_findings = analyze_content(flow.response.text, 'Response Body')
                        self.findings.extend(text_findings)
                    except UnicodeDecodeError:
                        # Skip binary content that can't be decoded
                        logger.debug(f"Skipping binary content from {flow.request.url}")
                        pass
                    
        except Exception as e:
            logger.error(f"Error processing response from {flow.request.url}: {e}")

# Global request handler instance
request_handler = RequestHandler()

def start_proxy(port: int = 8080):
    """Start the mitmproxy server."""
    try:
        logger.info(f"Starting mitmproxy on port {port}...")
        
        # Disable mitmproxy's logging to avoid event_loop issues
        import logging as py_logging
        mitmproxy_logger = py_logging.getLogger('mitmproxy')
        mitmproxy_logger.setLevel(py_logging.CRITICAL)
        mitmproxy_logger.handlers = []
        
        # Configure mitmproxy options
        options = Options(
            listen_port=port,
            ssl_insecure=True,
            showhost=True,
            http2=True,
        )
        
        # Start the proxy server
        master = DumpMaster(
            options=options,
            with_termlog=False,
            with_dumper=False,
        )
        
        # Add our request handler
        master.addons.add(RequestHandler())
        
        # Add our custom image view
        master.addons.add(load_custom_image_view(None))
        
        # Start the proxy in its own event loop
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Monkey patch the event_loop attribute
        master.event_loop = loop
        
        # Run the proxy
        def run_master():
            try:
                loop.run_until_complete(master.run())
            except Exception as e:
                logger.error(f"Proxy runtime error: {e}")
        
        import threading
        proxy_thread = threading.Thread(target=run_master, daemon=True)
        proxy_thread.start()
        
        logger.info("mitmproxy started successfully with custom views")
        return master
        
    except Exception as e:
        logger.error(f"Failed to start mitmproxy: {e}")
        raise

def start_proxy_in_thread(port: int = 8080):
    """Start the mitmproxy server in a separate thread."""
    try:
        return start_proxy(port)
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        raise

# Global variables for proxy management
mitm_thread = None
mitm_running = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
async def scan():
    global mitm_thread, mitm_running
    
    # Validate request body
    if not request.json:
        return jsonify({'error': 'Invalid request format. JSON body required.'}), 400
    
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    
    # Parse and validate URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid URL: {str(e)}'}), 400
    
    try:
        # Reset findings
        request_handler.findings = []
        
        # Start mitmproxy if not already running
        if not mitm_running:
            mitm_thread = start_proxy_in_thread(8080)
            mitm_running = True
            logger.info("Started mitmproxy in background")
            
            # Give the proxy a moment to start
            await asyncio.sleep(2)
        
        # Configure browser to use our proxy
        proxy = {
            'server': 'http://localhost:8080',
            'bypass': 'localhost,127.0.0.1',
        }
        
        # Launch browser with Playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, proxy=proxy)
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1280, 'height': 1024},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            )
            
            page = await context.new_page()
            
            try:
                # Navigate to the URL with a more reliable wait strategy
                logger.info(f"Navigating to {url}")
                try:
                    response = await page.goto(url, wait_until='domcontentloaded', timeout=30000)
                    logger.info(f"Page loaded, status: {response.status if response else 'unknown'}")
                except Exception as e:
                    logger.warning(f"Page navigation warning: {e}")
                    # Try to continue anyway if the page partially loaded
                    response = None
                
                # Wait a bit for JavaScript to execute
                logger.info("Waiting for dynamic content...")
                await asyncio.sleep(3)
                
                # Try to wait for network idle, but don't fail if it times out
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                    logger.info("Network idle detected")
                except Exception as e:
                    logger.warning(f"Network idle timeout (continuing anyway): {e}")
                
                # Quick scroll to trigger lazy-loaded content
                logger.info("Scrolling page...")
                try:
                    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.warning(f"Error scrolling: {e}")
                
                # Get the final page content and analyze it properly
                logger.info("Extracting page content...")
                content = await page.content()
                logger.info(f"Page content extracted ({len(content)} bytes)")
                
                # Parse HTML and analyze only JavaScript and config data
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Analyze inline scripts
                    scripts = soup.find_all('script')
                    logger.info(f"Found {len(scripts)} script tags, analyzing...")
                    for idx, script in enumerate(scripts):
                        if script.string and len(script.string.strip()) > 0:
                            script_findings = analyze_content(script.string, f'Page Script #{idx+1}')
                            request_handler.findings.extend(script_findings)
                    
                    # Analyze data attributes that might contain config
                    logger.info("Analyzing data attributes...")
                    for tag in soup.find_all(True):  # Find all tags
                        if hasattr(tag, 'attrs') and tag.attrs:
                            for attr, value in tag.attrs.items():
                                if attr.startswith('data-') and isinstance(value, str) and len(value) > 20:
                                    attr_findings = analyze_content(value, f'HTML Attribute: {attr}')
                                    request_handler.findings.extend(attr_findings)
                    
                    logger.info(f"Analysis complete. Total findings: {len(request_handler.findings)}")
                except Exception as e:
                    logger.error(f"Error parsing page content: {e}", exc_info=True)
                
            except Exception as e:
                logger.error(f"Error during page interaction: {e}", exc_info=True)
                return jsonify({
                    'error': f'Failed to load page: {str(e)}. The website may be unreachable or blocking automated access.'
                }), 500
                
            finally:
                try:
                    await browser.close()
                except Exception as e:
                    logger.warning(f"Error closing browser: {e}")
        
        # Process all findings - merge duplicates based on value and location
        findings = []
        value_location_map = {}  # Maps (value, source, line) to best finding
        
        # Patterns that are essentially the same (keep the more specific one)
        pattern_priority = {
            'google_api_key': 1,  # General Google API key
            'oauth_token': 1,
        }
        
        # Deduplicate findings - merge duplicates based on value, source, and line
        for finding in request_handler.findings:
            value = finding.get('value', finding.get('match', ''))
            source = finding.get('source', '')
            line = finding.get('line', 0)
            finding_type = finding.get('type', '')
            
            # Create key based on value and location (not type)
            key = (value, source, line)
            
            if key not in value_location_map:
                value_location_map[key] = finding
            else:
                # We have a duplicate - keep the better one
                existing = value_location_map[key]
                existing_type = existing.get('type', '')
                existing_severity = existing.get('severity', 'low')
                new_severity = finding.get('severity', 'low')
                
                # Priority: more specific pattern > higher severity > existing one
                existing_priority = pattern_priority.get(existing_type, 999)
                new_priority = pattern_priority.get(finding_type, 999)
                
                should_replace = False
                
                # If new pattern is more specific (lower priority number), use it
                if new_priority < existing_priority:
                    should_replace = True
                # If same priority, prefer higher severity
                elif new_priority == existing_priority:
                    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                    if severity_order.get(new_severity, 0) > severity_order.get(existing_severity, 0):
                        should_replace = True
                
                if should_replace:
                    value_location_map[key] = finding
        
        findings = list(value_location_map.values())
        
        # Categorize findings by severity
        critical_severity = [f for f in findings if f.get('severity') == 'critical']
        high_severity = [f for f in findings if f.get('severity') == 'high']
        medium_severity = [f for f in findings if f.get('severity') == 'medium']
        low_severity = [f for f in findings if f.get('severity') == 'low']
        
        # Prepare the response
        response_data = {
            'url': url,
            'status': 'completed',
            'findings': findings,
            'scan_summary': {
                'total_findings': len(findings),
                'critical_severity': len(critical_severity),
                'high_severity': len(high_severity),
                'medium_severity': len(medium_severity),
                'low_severity': len(low_severity),
            },
            'details': {
                'requests_analyzed': len(request_handler.findings),
                'unique_findings': len(findings),
                'scan_timestamp': datetime.now().isoformat(),
            }
        }
        
        return jsonify(response_data)
        
    except asyncio.TimeoutError:
        return jsonify({
            'error': 'Scan timeout: The website took too long to respond. Please try again or scan a different URL.',
            'status': 'error'
        }), 408
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during scan: {e}")
        return jsonify({
            'error': f'Network error: Unable to reach {url}. Please check the URL and try again.',
            'status': 'error'
        }), 400
        
    except Exception as e:
        logger.exception("Unexpected error during scan")
        error_message = str(e)
        
        # Provide more helpful error messages for common issues
        if 'playwright' in error_message.lower():
            error_message = 'Browser automation error. Please ensure Playwright browsers are installed (run: playwright install chromium)'
        elif 'connection refused' in error_message.lower():
            error_message = 'Unable to connect to the website. Please check the URL and try again.'
        elif 'timeout' in error_message.lower():
            error_message = 'The scan timed out. The website may be slow or unresponsive.'
        else:
            error_message = f'An unexpected error occurred: {error_message}'
            
        return jsonify({
            'error': error_message,
            'status': 'error'
        }), 500

@app.route('/stop-proxy', methods=['POST'])
def stop_proxy():
    """Stop the mitmproxy server."""
    global mitm_thread, mitm_running
    
    if mitm_running and mitm_thread:
        try:
            # This is a simple approach - in production, you'd want to properly shut down mitmproxy
            mitm_running = False
            if mitm_thread.is_alive():
                mitm_thread.join(timeout=5)
            return jsonify({'status': 'stopped'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'status': 'not_running'})

@app.route('/status', methods=['GET'])
def status():
    """Get the current status of the scanner."""
    global mitm_running
    
    return jsonify({
        'status': 'running' if mitm_running else 'stopped',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'features': [
            'mitmproxy integration',
            'playwright browser automation',
            'comprehensive secret detection',
            'real-time network monitoring'
        ]
    })

def install_browser_deps():
    """Install browser dependencies for Playwright."""
    import sys
    import subprocess
    
    try:
        logger.info("Installing Playwright browsers...")
        subprocess.run([sys.executable, '-m', 'playwright', 'install', 'chromium'], check=True)
        subprocess.run([sys.executable, '-m', 'playwright', 'install-deps'], check=True)
        logger.info("Browser dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install browser dependencies: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Install browser dependencies if needed
    install_browser_deps()
    
    # Start the Flask app on port 5002 (5000 is often used by AirPlay on macOS)
    app.run(host='0.0.0.0', port=5002, debug=True)
