/**
 * Secret detection patterns for KeyLeak Detector.
 * Ported from the Python web app + GitLeaks patterns.
 *
 * Each entry: { pattern: RegExp, severity: 'high'|'medium'|'low', description: string }
 */

const PATTERNS = {
  // --- Cloud Provider Credentials ---
  aws_key:                { pattern: /AKIA[0-9A-Z]{16}/g, severity: 'high', description: 'AWS Access Key ID' },
  aws_secret:             { pattern: /(?:aws)(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/gi, severity: 'high', description: 'AWS Secret Access Key' },
  aws_account_id:         { pattern: /\b(?:aws[_-]?account[_-]?id|account[_-]?id|aws[_-]?id)[=: ]*['"]?([0-9]{4}[-]?[0-9]{4}[-]?[0-9]{4})['"]?/gi, severity: 'medium', description: 'AWS Account ID' },
  google_api_key:         { pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high', description: 'Google API Key' },
  google_oauth:           { pattern: /ya29\.[0-9A-Za-z\-_]+/g, severity: 'medium', description: 'Google OAuth Token' },
  google_service_account: { pattern: /"type":\s*"service_account"[\s\S]*?"project_id":\s*"[^"]*"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY-----/g, severity: 'high', description: 'Google Cloud Service Account Key' },
  firebase:               { pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: 'high', description: 'Firebase API Key' },
  heroku_api_key:         { pattern: /[hH][eE][rR][oO][kK][uU][\s-]?[aA][pP][iI][\s-]?[kK][eE][yY][\s-:]*['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?/g, severity: 'high', description: 'Heroku API Key' },

  // --- Service Credentials ---
  stripe_key:             { pattern: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}/g, severity: 'high', description: 'Stripe API Key' },
  stripe_restricted_key:  { pattern: /rk_(?:test|live)_[0-9a-zA-Z]{24,}/g, severity: 'high', description: 'Stripe Restricted Key' },
  slack_token:            { pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}/g, severity: 'high', description: 'Slack Token' },
  slack_webhook:          { pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, severity: 'high', description: 'Slack Webhook URL' },
  github_pat:             { pattern: /ghp_[0-9a-zA-Z]{36}/g, severity: 'high', description: 'GitHub Personal Access Token' },
  github_fine_grained_pat:{ pattern: /github_pat_[0-9a-zA-Z_]{82}/g, severity: 'high', description: 'GitHub Fine-Grained PAT' },
  github_oauth:           { pattern: /gho_[0-9a-zA-Z]{36}/g, severity: 'high', description: 'GitHub OAuth Token' },
  gitlab_token:           { pattern: /glpat-[0-9a-zA-Z\-]{20}/g, severity: 'high', description: 'GitLab Token' },
  npm_token:              { pattern: /npm_[a-zA-Z0-9\-_]{36}/g, severity: 'high', description: 'npm Token' },
  sendgrid_api_key:       { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'high', description: 'SendGrid API Key' },
  square_access_token:    { pattern: /sq0atp-[0-9A-Za-z\-_]{22}/g, severity: 'high', description: 'Square Access Token' },
  square_oauth_secret:    { pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g, severity: 'high', description: 'Square OAuth Secret' },
  pypi_upload_token:      { pattern: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/g, severity: 'high', description: 'PyPI Upload Token' },
  mailgun_api_key:        { pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'high', description: 'Mailgun API Key' },
  mailchimp_api_key:      { pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g, severity: 'high', description: 'Mailchimp API Key' },
  twilio_api_key:         { pattern: /SK[0-9a-fA-F]{32}/g, severity: 'high', description: 'Twilio API Key' },

  // --- LLM / AI Provider Keys ---
  openai_api_key:         { pattern: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g, severity: 'high', description: 'OpenAI API Key' },
  anthropic_api_key:      { pattern: /sk-ant-[a-zA-Z0-9\-_]{95,}/g, severity: 'high', description: 'Anthropic API Key' },
  huggingface_token:      { pattern: /hf_[a-zA-Z0-9]{32,}/g, severity: 'high', description: 'Hugging Face Token' },
  openrouter_api_key:     { pattern: /sk-or-v1-[a-zA-Z0-9]{64,}/g, severity: 'high', description: 'OpenRouter API Key' },
  replicate_api_key:      { pattern: /r8_[a-zA-Z0-9]{40,}/g, severity: 'high', description: 'Replicate API Key' },
  perplexity_api_key:     { pattern: /pplx-[a-zA-Z0-9]{40,}/g, severity: 'high', description: 'Perplexity AI API Key' },
  anyscale_api_key:       { pattern: /esecret_[a-zA-Z0-9]{40,}/g, severity: 'high', description: 'Anyscale API Key' },
  groq_api_key:           { pattern: /gsk_[a-zA-Z0-9]{52}/g, severity: 'high', description: 'Groq API Key' },

  // --- Database Credentials ---
  mongo_uri:              { pattern: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\-.]+\/\w+/g, severity: 'medium', description: 'MongoDB Connection String' },
  postgres_uri:           { pattern: /postgres(?:ql)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-.]+:[0-9]+\/\w+/g, severity: 'medium', description: 'PostgreSQL Connection String' },
  mysql_uri:              { pattern: /mysql(?:2)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-.]+:[0-9]+\/\w+/g, severity: 'medium', description: 'MySQL Connection String' },
  redis_uri:              { pattern: /redis(?:\+srv)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\-.]+:[0-9]+\/\w+/g, severity: 'medium', description: 'Redis Connection String' },

  // --- Authentication ---
  jwt_token:              { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'medium', description: 'JWT Token' },
  bearer_token:           { pattern: /bearer[\s=:]+([a-zA-Z0-9_\-]{20,})/gi, severity: 'medium', description: 'Bearer Token' },
  basic_auth:             { pattern: /basic[\s=:]+([a-zA-Z0-9+/=]+)/gi, severity: 'medium', description: 'Basic Auth Credentials' },
  api_key:                { pattern: /(?:api[_-]?key|apikey|api[_-]?token|api[_-]?secret)[=: ]*['"]?([a-z0-9_\-]{20,})['"]?/gi, severity: 'medium', description: 'API Key' },
  session_token:          { pattern: /session[_-]?token[=: ]*['"]?([a-f0-9]{64})['"]?/gi, severity: 'medium', description: 'Session Token' },

  // --- Sensitive Data ---
  private_key:            { pattern: /-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY[\s\S]*?-----END (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----/g, severity: 'high', description: 'Private Key' },
  credit_card:            { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g, severity: 'high', description: 'Credit Card Number' },
  private_ip:             { pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, severity: 'medium', description: 'Private IP Address' },

  // --- Sensitive URLs ---
  webhook_url:            { pattern: /https?:\/\/[^\s'"]+webhook[^\s'"]+/gi, severity: 'medium', description: 'Webhook URL' },
  http_basic_auth:        { pattern: /(?:https?:\/\/)([a-zA-Z0-9_-]+):([^@\s]+)@/gi, severity: 'medium', description: 'HTTP Basic Auth in URL' },
};

// Pre-compile all patterns once
const COMPILED_PATTERNS = {};
for (const [name, entry] of Object.entries(PATTERNS)) {
  try {
    // Clone the regex to ensure fresh lastIndex on each use
    COMPILED_PATTERNS[name] = entry;
  } catch (e) {
    console.warn(`[KeyLeak] Skipping invalid pattern: ${name}`, e);
  }
}

export { PATTERNS, COMPILED_PATTERNS };
