# cpoise

CPoise is a security testing tool for detecting Cache Poisoned Denial of Service (CPDoS) and Cache Deception vulnerabilities in web applications, reverse proxies, and CDNs.

It helps security researchers and penetration testers identify unsafe caching behavior, cache key inconsistencies, and request handling issues that may lead to content poisoning or unintended exposure of sensitive data.

## ⚙️ Features
- Detects Cache Poisoned DoS (CPDoS) vulnerabilities
- Detects Web Cache Deception vulnerabilities
- Supports single URL and bulk scanning
- Raw HTTP request replay support
- Proxy support (e.g., Burp Suite)
- Optional SSL verification bypass
- Automated exploit PoC opening in browser

## 📦 Installation

Install dependencies:
```bash
pip3 install -r requirements.txt
```

## 🔍 Scan a Single Target
```bash
python3 cpoise.py -u target.com -a
```

## 📁 Scan Multiple URLs
```bash
python3 cpoise.py -f urls.txt -a
```
> ⚠️ For large-scale scans, use one of the following arguments:
- `--continue-on-fail` → continue even if no cache evidence is found
- `--skip-on-fail` → skip hosts without cache evidence (recommended for large lists)  

## 📄 Scan Using Raw HTTP Request
```bash
python3 cpoise.py -r req.txt -a
```

## 🔗 Proxy Support (Burp Suite)

To route traffic through Burp Suite:
```bash
python3 cpoise.py -u target.com -a  --proxy http://127.0.0.1:8080 -k
```

## 🌐 Optional Features
Open Exploit PoC Automatically
```bash
-b
```
Automatically opens a browser with the exploit PoC when a vulnerability is found. (Not recommended to use when doing mass scanning).


## 🎯 Recommended Learning
If you're new to CPDoS or Cache Deception, it is highly recommended to test the tool against PortSwigger Web Security Academy [labs](https://portswigger.net/web-security/web-cache-deception). These labs provide a safe environment to understand how caching vulnerabilities work in practice.