# vuln-Cookie-Security-Analyzer

A command-line tool to analyze cookies for security flags (HttpOnly, Secure, SameSite) and report potential vulnerabilities based on their absence or misconfiguration. Cookies are analyzed on the response received, including error responses, and only cookie names, attributes, and flags are reported: cookie values are never printed. If a response sets no cookies, the run reports that nothing was analyzed and exits non-zero instead of printing a clean verdict.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-cookie-security-analyzer`

`pip install -r requirements.txt`

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:8080/cookies`

## Parameters
- `url`: The URL to analyze (required, positional).
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `--timeout`: Timeout in seconds for the request. Default: 10. Must be greater than 0.

## License
MIT License (see LICENSE).
