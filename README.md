# KeyLeak Detector

A web application that scans websites for potential API keys, secrets, and sensitive information leaks. This tool helps developers and security professionals identify and fix security vulnerabilities in their web applications.

**Related Project:** For validating and testing found credentials, check out [Keyleaksecret](https://github.com/0xSojalSec/Keyleaksecret) - a comprehensive tool for verifying 80+ types of API keys and secrets.

## Features

- Scans web pages for common secret patterns (API keys, passwords, tokens, etc.)
- Checks response headers for sensitive information
- Validates security headers
- User-friendly web interface
- Real-time scanning results
- Categorizes findings by severity

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd keyleak-detector
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install Playwright browsers (required for scanning):
   ```bash
   playwright install chromium
   playwright install-deps
   ```

## Usage

1. Start the application:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5002
   ```
   
   > **Note:** The app runs on port 5002 instead of 5000 as port 5000 is commonly used by AirPlay on macOS.

3. Enter the URL you want to scan in the input field and click "Scan Now"

4. View the results, which will show any potential security issues found

## How It Works

The application uses a combination of browser automation and network traffic analysis to find secrets:

1. **Browser Automation**: Uses Playwright to load the target website in a headless browser
2. **Network Monitoring**: Intercepts HTTP requests and responses using mitmproxy
3. **Content Analysis**: Analyzes JavaScript, HTML, headers, and dynamic content
4. **Pattern Matching**: Uses regex patterns to detect various types of secrets
5. **Smart Filtering**: Filters false positives using context-aware analysis
6. **Categorization**: Groups findings by severity (Critical, High, Medium, Low)

## Patterns Detected

The scanner detects 50+ types of sensitive information including:

**Cloud Provider Credentials:**
- AWS Access Keys & Secret Keys
- Google API Keys & OAuth Tokens
- Google Cloud Service Account Keys
- Google Vertex AI API Keys
- Firebase API Keys
- Heroku API Keys

**Service Credentials:**
- Stripe API Keys
- Slack Tokens
- GitHub Tokens & OAuth
- GitLab Tokens
- Mailgun, Mailchimp, Twilio API Keys
- npm Tokens

**LLM/AI Inference Provider Keys:**
- OpenAI API Keys (GPT-4, ChatGPT, etc.)
- Anthropic API Keys (Claude)
- Google Gemini & Vertex AI API Keys
- Hugging Face Tokens
- Cohere API Keys
- OpenRouter API Keys
- Replicate API Keys
- Together AI API Keys
- Perplexity AI API Keys
- Mistral AI API Keys
- AI21 Labs API Keys
- Anyscale API Keys
- DeepInfra API Keys
- Groq API Keys
- Fireworks AI API Keys

**Database Credentials:**
- MongoDB, PostgreSQL, MySQL, Redis connection strings
- SQL Server connection strings

**Authentication:**
- JWT Tokens
- Bearer Tokens
- OAuth Tokens
- Session Tokens
- Basic Auth credentials
- API Keys

**Sensitive Data:**
- Private SSH Keys
- Credit Card Numbers
- Social Security Numbers
- Email Addresses
- Phone Numbers

**Other:**
- Webhook URLs
- Callback URLs
- Hardcoded passwords
- Encrypted credentials in JavaScript

## Validating Found Secrets

When the scanner finds potential secrets, it provides **actionable recommendations** including:

- **Immediate actions** to take (rotate, revoke, etc.)
- **Validation commands** to test if the key is actually valid/active  
- **Specific curl commands** to verify key functionality
- **Best practices** for secure credential management

### Recommended Validation Tool

For comprehensive validation of found secrets, we recommend using [**Keyleaksecret**](https://github.com/0xSojalSec/Keyleaksecret) - a specialized tool that provides:

- **80+ service validation methods** (Slack, GitHub, AWS, Stripe, Twilio, etc.)
- **Automated testing** of key validity
- **Detailed status reporting** for each credential
- **Best practices** for responsible disclosure

### Quick Validation Examples

**Slack Token:**
```bash
curl -X POST "https://slack.com/api/auth.test?token=YOUR_TOKEN&pretty=1"
```

**GitHub Token:**
```bash
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
```

**Stripe API Key:**
```bash
curl https://api.stripe.com/v1/charges -u YOUR_KEY:
```

**AWS Access Key:**
```bash
aws sts get-caller-identity --no-cli-pager
```

**OpenAI API Key:**
```bash
curl https://api.openai.com/v1/models -H "Authorization: Bearer YOUR_KEY"
```

**Anthropic (Claude) API Key:**
```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model": "claude-3-opus-20240229", "max_tokens": 1024, "messages": [{"role": "user", "content": "test"}]}'
```

**Google Gemini API Key:**
```bash
curl "https://generativelanguage.googleapis.com/v1/models?key=YOUR_KEY"
```

**Google Vertex AI:**
```bash
# Test API key
curl "https://generativelanguage.googleapis.com/v1/models?key=YOUR_KEY"

# For service account - use gcloud CLI
gcloud auth activate-service-account --key-file=service-account-key.json
gcloud projects list
```

**Hugging Face Token:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://huggingface.co/api/whoami
```

**OpenRouter API Key:**
```bash
curl https://openrouter.ai/api/v1/auth/key -H "Authorization: Bearer YOUR_KEY"
```

**Replicate API Key:**
```bash
curl -H "Authorization: Token YOUR_KEY" https://api.replicate.com/v1/account
```

**Together AI / Groq / Mistral / Other Providers:**
```bash
# Most providers follow OpenAI-compatible format
curl https://api.PROVIDER.com/v1/models -H "Authorization: Bearer YOUR_KEY"
```

## Security Considerations

- **Only scan websites you own or have permission to scan**
- Be cautious when scanning production environments
- This tool is for **educational and security testing purposes only**
- Always handle scan results securely and responsibly
- If you find valid credentials, **rotate them immediately**
- Report findings through responsible disclosure when appropriate

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
