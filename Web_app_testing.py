import streamlit as st
import requests
import socket
import json

# Streamlit UI
st.title('Web Application Penetration Testing Tool')
st.subheader('Test for OWASP Top 10 Vulnerabilities and Subdomain Enumeration')

# Input field for domain or IP address
input_domain = st.text_input('Enter Domain Name or IP Address', '')

# Subdomain Enumeration using a public API (example: threatcrowd.org)
def enumerate_subdomains(domain):
    st.write('Enumerating subdomains using ThreatCrowd API...')
    try:
        response = requests.get(f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}')
        data = response.json()
        if 'subdomains' in data and data['subdomains']:
            return data['subdomains']
        else:
            return []
    except Exception as e:
        st.error(f"Error in enumerating subdomains: {e}")
        return []

# OWASP Top 10 Vulnerability Check (Example: Simple vulnerability scan using requests)
def check_owasp_top_10(domain):
    st.write('Checking for OWASP Top 10 vulnerabilities...')
    vulnerabilities = {
        "SQL Injection": False,
        "Cross Site Scripting (XSS)": False,
        "Broken Authentication": False,
        "Sensitive Data Exposure": False,
        "Security Misconfiguration": False,
        "Cross-Site Request Forgery (CSRF)": False,
        "Insecure Deserialization": False,
        "Using Components with Known Vulnerabilities": False,
        "Insufficient Logging & Monitoring": False
    }

    try:
        # Example: SQL Injection Test
        url = f"http://{domain}/?id=1'"
        response = requests.get(url)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            vulnerabilities["SQL Injection"] = True

        # Example: XSS Test
        xss_payload = "<script>alert('XSS')</script>"
        response = requests.get(f"http://{domain}/?q={xss_payload}")
        if xss_payload in response.text:
            vulnerabilities["Cross Site Scripting (XSS)"] = True

        # Additional vulnerability checks can be similarly implemented here...

        return vulnerabilities
    except Exception as e:
        st.error(f"Error in vulnerability check: {e}")
        return vulnerabilities

# Basic Port Scanning using socket
def scan_ports(domain):
    st.write(f'Scanning ports for {domain}...')
    open_ports = []
    common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 143, 3389]  # Common ports
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    except Exception as e:
        st.error(f"Error in port scanning: {e}")
        return []

if st.button('Run Penetration Test'):
    if input_domain:
        st.write(f"Running tests on {input_domain}...")
        
        # Step 1: Enumerate subdomains
        subdomains = enumerate_subdomains(input_domain)
        if subdomains:
            st.write(f"Found subdomains: {', '.join(subdomains)}")
        else:
            st.write("No subdomains found.")

        # Step 2: Run scans on the main domain and subdomains
        all_domains = [input_domain] + subdomains

        for domain in all_domains:
            st.write(f"Testing domain: {domain}")
            
            # Step 2.1: Port Scanning
            open_ports = scan_ports(domain)
            if open_ports:
                st.write(f"Open ports for {domain}: {', '.join(map(str, open_ports))}")
            else:
                st.write(f"No open ports found for {domain}")

            # Step 2.2: OWASP Top 10 Vulnerability Scanning
            vulnerabilities = check_owasp_top_10(domain)
            st.write(f"OWASP Top 10 Vulnerabilities for {domain}:")
            st.json(vulnerabilities)
    else:
        st.error('Please enter a valid domain name or IP address.')
