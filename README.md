# 🛡️ HeaderCheck – HTTP Security Header Vulnerability Scanner

HeaderCheck is a lightweight Python-based tool designed to analyze HTTP response security headers and identify missing or misconfigured headers that may expose a web application to common security risks. The scanner evaluates a target website against widely recommended HTTP security headers and provides detailed explanations of their purpose, associated vulnerabilities, and recommended configurations.

This project was developed as a beginner-friendly cybersecurity tool to demonstrate the importance of secure HTTP header configurations and provide hands-on experience in web security assessment.

---

## 📌 Features

* Checks the presence of the following security headers:

  * Strict-Transport-Security (HSTS)
  * Content-Security-Policy (CSP)
  * X-Content-Type-Options
  * X-Frame-Options
  * Referrer-Policy
  * Permissions-Policy

* Displays a summary of:

  * Present security headers
  * Missing security headers

* Performs detailed analysis for each header including:

  * Purpose of the header
  * Security benefits
  * Potential attacks if missing
  * Recommended configuration
  * Basic configuration validation

* Displays HTTP response status code along with its meaning.

* Detects common weak configurations such as:

  * Missing HSTS `max-age`
  * CSP using `unsafe-inline`
  * CSP using `unsafe-eval`
  * CSP containing wildcard (`*`)
  * Incorrect `X-Content-Type-Options` values
  * Weak `X-Frame-Options` configuration

---

## ⚙️ Technologies Used

* Python 3
* Requests Library

---

## 📂 Project Structure

```
HeaderCheck/
│
├── headercheck.py
├── README.md
└── requirements.txt
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/HeaderCheck.git
cd HeaderCheck
```

Install dependencies:

```bash
pip install -r requirements.txt
```

or

```bash
pip install requests
```

---

## ▶️ Usage

Run the scanner:

```bash
python headercheck.py
```

Enter the target website when prompted:

```
Enter target URL:
https://example.com
```

---

## 📖 Sample Output

```
==========================================================
WEBSITE SECURITY HEADER SCANNER
==========================================================

Target URL : https://example.com

Status Code : 200
Meaning     : OK - Request successful.

----------------------------------------------------------

Security Header Summary

✓ Present Headers
• Strict-Transport-Security
• X-Frame-Options

✗ Missing Headers
• Content-Security-Policy
• Permissions-Policy

----------------------------------------------------------

Detailed Security Analysis

Header: Content-Security-Policy

Status : Missing

Purpose:
Controls which resources the browser is allowed to load.

Vulnerable To:
Cross-Site Scripting (XSS)
Code Injection

Recommendation:
Implement a strict Content-Security-Policy to restrict resource loading.
```

---

## 🔒 Security Headers Covered

| Header                    | Purpose                                                                           |
| ------------------------- | --------------------------------------------------------------------------------- |
| Strict-Transport-Security | Enforces HTTPS communication and protects against SSL stripping attacks.          |
| Content-Security-Policy   | Helps mitigate Cross-Site Scripting (XSS) and content injection attacks.          |
| X-Content-Type-Options    | Prevents browsers from MIME-type sniffing.                                        |
| X-Frame-Options           | Protects against Clickjacking attacks.                                            |
| Referrer-Policy           | Controls the amount of referrer information shared with external websites.        |
| Permissions-Policy        | Restricts access to browser features such as camera, microphone, and geolocation. |

---

## ⚠️ Limitations

* Performs passive header analysis only.
* Does not exploit or actively test vulnerabilities.
* Does not evaluate SSL/TLS configurations.
* Does not perform authentication or session security testing.
* CSP validation is limited to common insecure directives and is not a complete policy audit.

---

## 💡 Future Improvements

* Export scan results to JSON, CSV, or PDF.
* Scan multiple websites from a file.
* Add SSL/TLS security checks.
* Generate a vulnerability severity score.
* Produce HTML reports.
* Implement multi-threaded scanning for bulk analysis.
* Add support for additional HTTP security headers.

---

## 🎯 Learning Objectives

This project was built to strengthen understanding of:

* HTTP response headers
* Web application security fundamentals
* Common web vulnerabilities
* Python scripting
* Security automation
* Vulnerability assessment concepts

---

## 📜 Disclaimer

This tool is intended for educational purposes, security research, and authorized security assessments only. Always obtain proper permission before scanning systems that you do not own or have explicit authorization to test.

---

## 👨‍💻 Author

**Harsh Thacker**

Cybersecurity Enthusiast | Red Teaming Aspirant
