# 🔍 Vulnerability Scanner by Shoaib

A lightweight yet powerful Python-based vulnerability scanner that performs comprehensive TCP port scanning, banner grabbing, and HTTP security header analysis.

---

## 🚀 Features

- ✅ Scans all **65535 TCP ports** on a target IP or domain  
- ✅ **Grabs service banners** from open ports  
- ✅ Analyzes **HTTP response headers** for missing security directives:
  - `X-Frame-Options`
  - `X-XSS-Protection`
  - `Content-Security-Policy`
- ✅ Shows **animated spinner** to keep user engaged during scanning  
- ✅ Generates a **professional scan report** saved to a `.txt` file  
- ✅ Friendly CLI interaction personalized for **Shoaib**

---

## 🛠 Requirements

- Python 3.x  
- `requests` library

Install with:

```bash
pip install requests
