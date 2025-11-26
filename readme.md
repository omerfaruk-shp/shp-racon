 Ultimate Security Scanner v9.0 - README

🛡️ Ultimate Security Scanner (v9.0)
====================================

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Active-success.svg)

**Ultimate Security Scanner** is a comprehensive, Python-based _All-in-One_ reconnaissance and penetration testing tool. It performs both **passive** and **active** analysis on a target, providing a real-time terminal dashboard and generating detailed professional reports.

* * *

🚀 Features
-----------

This tool integrates **14 different security modules** into a single script:

### 🔍 Passive Reconnaissance

*   **Whois Lookup:** Retrieves domain registration details and organization info.
*   **DNS & Cloudflare Detector:** Enumerates DNS records (A, MX, NS, TXT) and detects Cloudflare WAF.
*   **SSL Certificate Analysis:** Checks certificate validity, issuer, and expiration date.
*   **Subdomain Enumeration:** Uses `crt.sh` to find hidden subdomains.
*   **IP Location:** Geolocation and ISP information of the target server.

### ⚔️ Active Scanning & Attacks

*   **Zone Transfer (AXFR):** Checks for DNS Zone Transfer vulnerabilities.
*   **Port Scanning:** Scans critical ports (21, 22, 80, 443, 3306, etc.) for open services.
*   **Admin Panel Finder:** Brute-forces common admin paths (e.g., `/wp-admin`, `/cpanel`).
*   **Sensitive File Hunt:** Scans for critical files like `.env`, `.git/HEAD`, `robots.txt`.
*   **WP User Enumeration:** Extracts usernames from WordPress JSON API.
*   **Email Harvester:** Scrapes the website source code for exposed email addresses.

### 🛠️ Tools & Utilities

*   **HTTP Headers & WAF:** Analyzes security headers and detects Web Application Firewalls.
*   **Traceroute:** Maps the network path to the target server.
*   **Link Grabber (TXT Export):** Extracts all external links and saves them to a `LINKS_target.txt` file.

* * *

📦 Installation
---------------

To run this tool, you need **Python 3.x** installed on your system.

### 1\. Install Dependencies

Open your terminal and run the following command:

    pip install requests dnspython python-whois rich

### 2\. Download

Save the script as `scanner.py` in your working directory.

* * *

💻 Usage
--------

Run the script directly from the terminal:

    python scanner.py

1.  Enter the **Target URL** when prompted (e.g., `google.com`).
2.  Wait for the automated scan to complete (Dashboard view).
3.  Check the output files generated in the same directory.

* * *

📊 Outputs & Reporting
----------------------

The tool generates two files upon completion:

> **1\. HTML Report:** `SCAN_REPORT_target_com.html`  
> A dark-themed, professional HTML report containing all findings, color-coded by severity.

> **2\. Link List:** `LINKS_target_com.txt`  
> A raw text file containing every external link found on the target website.

* * *

⚠️ Legal Disclaimer
-------------------

This tool is intended for **educational purposes and authorized security testing only**. Scanning targets without prior consent is illegal. The developer assumes no liability for any misuse of this tool.

* * *

Developed by **Faruk** | Python Cyber Security Toolkit Ultimate Security Scanner v9.0 - README

🛡️ Ultimate Security Scanner (v9.0)
====================================

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Active-success.svg)

**Ultimate Security Scanner** is a comprehensive, Python-based _All-in-One_ reconnaissance and penetration testing tool. It performs both **passive** and **active** analysis on a target, providing a real-time terminal dashboard and generating detailed professional reports.

* * *

🚀 Features
-----------

This tool integrates **14 different security modules** into a single script:

### 🔍 Passive Reconnaissance

*   **Whois Lookup:** Retrieves domain registration details and organization info.
*   **DNS & Cloudflare Detector:** Enumerates DNS records (A, MX, NS, TXT) and detects Cloudflare WAF.
*   **SSL Certificate Analysis:** Checks certificate validity, issuer, and expiration date.
*   **Subdomain Enumeration:** Uses `crt.sh` to find hidden subdomains.
*   **IP Location:** Geolocation and ISP information of the target server.

### ⚔️ Active Scanning & Attacks

*   **Zone Transfer (AXFR):** Checks for DNS Zone Transfer vulnerabilities.
*   **Port Scanning:** Scans critical ports (21, 22, 80, 443, 3306, etc.) for open services.
*   **Admin Panel Finder:** Brute-forces common admin paths (e.g., `/wp-admin`, `/cpanel`).
*   **Sensitive File Hunt:** Scans for critical files like `.env`, `.git/HEAD`, `robots.txt`.
*   **WP User Enumeration:** Extracts usernames from WordPress JSON API.
*   **Email Harvester:** Scrapes the website source code for exposed email addresses.

### 🛠️ Tools & Utilities

*   **HTTP Headers & WAF:** Analyzes security headers and detects Web Application Firewalls.
*   **Traceroute:** Maps the network path to the target server.
*   **Link Grabber (TXT Export):** Extracts all external links and saves them to a `LINKS_target.txt` file.

* * *

📦 Installation
---------------

To run this tool, you need **Python 3.x** installed on your system.

### 1\. Install Dependencies

Open your terminal and run the following command:

    pip install requests dnspython python-whois rich

### 2\. Download

Save the script as `scanner.py` in your working directory.

* * *

💻 Usage
--------

Run the script directly from the terminal:

    python scanner.py

1.  Enter the **Target URL** when prompted (e.g., `google.com`).
2.  Wait for the automated scan to complete (Dashboard view).
3.  Check the output files generated in the same directory.

* * *

📊 Outputs & Reporting
----------------------

The tool generates two files upon completion:

> **1\. HTML Report:** `SCAN_REPORT_target_com.html`  
> A dark-themed, professional HTML report containing all findings, color-coded by severity.

> **2\. Link List:** `LINKS_target_com.txt`  
> A raw text file containing every external link found on the target website.

* * *

⚠️ Legal Disclaimer
-------------------

This tool is intended for **educational purposes and authorized security testing only**. Scanning targets without prior consent is illegal. The developer assumes no liability for any misuse of this tool.

* * *

Developed by **Faruk** | Python Cyber Security Toolkit
