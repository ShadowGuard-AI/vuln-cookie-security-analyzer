# vuln-Cookie-Security-Analyzer
A command-line tool to analyze cookies for security flags (HttpOnly, Secure, SameSite) and report potential vulnerabilities based on their absence or misconfiguration. Cookies are analyzed on every response received, including error responses, and only cookie names, attributes, and flags are reported: cookie values are never printed. If a response sets no cookies, the run reports that nothing was analyzed and exits non-zero instead of printing a clean verdict. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-cookie-security-analyzer`

## Usage
`./vuln-cookie-security-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `--timeout`: Timeout in seconds for the request. Default: 10

## License
Copyright (c) ShadowStrikeHQ
