# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security tab → Report a vulnerability** on this repository, or directly at
<https://github.com/Barkatzineddine/reconscope/security/advisories/new>.

Do not open a public issue for security problems. You will get an acknowledgement within
5 working days, and a fix or mitigation plan once the report is confirmed.

## Scope

- `reconscope` sends traffic to the hosts you point it at. The authorization gate
  (`src/reconscope/scope.py`) is a security boundary: any way to make the scanner contact a
  host or port that the scope file does not explicitly allow is a vulnerability.
- The HTML report (`src/reconscope/report.py`) embeds values collected from the network
  (banners, certificate fields, HTTP titles, DNS records). It must not run code or load
  remote resources from those values. It is protected by HTML-escaping and a Content Security
  Policy that only allows its own inline style, identified by its hash.

## Supported versions

Only the latest commit on `main` is supported.
