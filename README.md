# **Network Security Scanner**

A Python-based multi-functional network utility tool designed for penetration testers, security enthusiasts, and IT professionals. The script includes features for port scanning, network sniffing, WordPress vulnerability discovery, and directory brute-forcing.

---

## **Features**
1. **Nmap Port Scanning**  
   Quickly scan open ports and services on a target system using Nmap's Python bindings.

2. **Network Sniffing**  
   Capture and display live network traffic from a specified interface using Scapy.

3. **WordPress Vulnerability Scanning**  
   Detect common WordPress vulnerabilities by checking standard endpoints.

4. **Directory Brute Forcing**  
   Perform directory brute force attacks on a target web server using a customizable wordlist.

---

## **Installation**

### **Dependencies**
This script relies on several Python libraries. Install the required dependencies using `pip`:

```bash
pip install nmap scapy requests
```

### **Setup**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/networkscanner.git
   cd networkscanner
   ```

2. Make the script executable:
   ```bash
   chmod +x networkscanner.py
   ```

3. Run the script:
   ```bash
   python networkscanner.py
   ```

---

## **Usage**

### **Menu Options**
The script presents an interactive menu:

```
============================================
[1] Nmap Port Scanning
[2] Network Sniffing (Scapy)
[3] WordPress Vulnerability Scanning
[4] Directory Brute Forcing
[0] Exit
============================================
```

### **Examples**

#### 1. **Nmap Port Scanning**
Enter the target IP or domain to scan. Example:
```
Target IP or Domain: 192.168.1.1
```

#### 2. **Network Sniffing**
Specify the network interface (e.g., `eth0`, `wlan0`) to capture packets. It captures 10 packets by default.

#### 3. **WordPress Vulnerability Scanning**
Enter the target WordPress site URL. Example:
```
Target WordPress site: http://example.com
```

#### 4. **Directory Brute Forcing**
Provide the target site URL and a wordlist file. Example:
```
Target site: http://example.com
Wordlist path: /path/to/wordlist.txt
Threads (recommended: 5): 5
```

---

## **Warnings**
- **Educational Use Only:** This tool is intended for learning and authorized testing purposes. Unauthorized use against systems without explicit consent is illegal.
- **Secure Your System:** Test in isolated or controlled environments to avoid unintended consequences.

---

## **Author**
This project was created by **UMUTKAYA** for **ZZCODEOFFICIAL**.

---

## **License**
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## **Contributing**
Feel free to submit issues or feature requests via the [GitHub Issues](https://github.com/yourusername/networkscanner/issues) page. Contributions are welcome!
