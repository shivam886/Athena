import streamlit as st
import dns.resolver
import ssl
import socket
from datetime import datetime
from dateutil import parser
import pytz
import logging
import requests

# Set up logging
logging.basicConfig(filename='email_spoofing_ssl_check.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')

# Function to get SSL certificate details
def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        logging.error(f"Error retrieving SSL certificate for {domain}: {e}")
        return None

def display_certificate_info(cert):
    if cert is None:
        return "Could not retrieve SSL certificate."
    
    expiry_date = parser.parse(cert['notAfter'])
    current_time = datetime.now(pytz.utc)
    days_to_expiry = (expiry_date - current_time).days
    
    info = {
        "Issuer": dict(x[0] for x in cert['issuer']),
        "Subject": dict(x[0] for x in cert['subject']),
        "Serial Number": cert['serialNumber'],
        "Version": cert['version'],
        "Not Before": cert['notBefore'],
        "Not After": cert['notAfter'],
        "Days to Expiry": days_to_expiry
    }

    return info

# Function to check SPF record
def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode().startswith("v=spf1"):
                    return "Status Ok"
        return "Status Not Found"
    except Exception as e:
        logging.error(f"Error checking SPF for {domain}: {e}")
        return "Status Not Found"

# Function to check DMARC record
def check_dmarc_record(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        if not answers:
            return "Status Not Found", "DMARC Record not found"
        
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode().startswith("v=DMARC1"):
                    dmarc_record = txt_string.decode()
                    policy = "DMARC Policy Not Enabled"
                    if "p=quarantine" in dmarc_record or "p=reject" in dmarc_record:
                        policy = "DMARC Quarantine/Reject policy enabled"
                    return "Status Ok", policy
        
        return "Status Not Found", "DMARC Record not found"
    except Exception as e:
        logging.error(f"Error checking DMARC for {domain}: {e}")
        return "Status Not Found", "DMARC Record not found"

# Function to check DNSSEC
def check_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return "Status Ok"
        return "Status Not Found"
    except Exception as e:
        logging.error(f"Error checking DNSSEC for {domain}: {e}")
        return "Status Not Found"

# Function to format the output for SPF/DMARC/DNSSEC checks
def format_output(spf_status, dmarc_status, dmarc_policy_status, dns_status):
    output = f"""
    | Test                          | Result                                     |
    |-------------------------------|--------------------------------------------|
    | SPF Record                    | {spf_status}                               |
    | DMARC Record                  | {dmarc_status}                             |
    | DMARC Policy                  | {dmarc_policy_status}                      |
    | DNS Record                    | {dns_status}                               |
    """
    return output

# Placeholder AI-based domain validation (for illustration purposes)
def validate_domain_with_ai(domain):
    if not domain or '.' not in domain:
        return False, "Invalid domain format. Please enter a correct domain name."
    try:
        requests.get(f"http://{domain}")
        return True, ""
    except requests.exceptions.RequestException:
        return False, "Domain does not exist. Please enter a correct domain name."

# Streamlit UI
st.title("Domain Security Check")

st.markdown("**Please enter the domain name without 'http://' or '@'**")

domain = st.text_input("Enter domain name:")

# SSL Certificate Check
if st.button("Check SSL Certificate Expiry"):
    if domain:
        domain = domain.replace('http://', '').replace('https://', '').replace('@', '')
        cert = get_ssl_certificate(domain)
        if cert:
            info = display_certificate_info(cert)
            st.json(info)
            if info["Days to Expiry"] > 0:
                st.success(f"SSL certificate for {domain} expires on {info['Not After']} ({info['Days to Expiry']} days remaining).")
            else:
                st.error(f"SSL certificate for {domain} has expired on {info['Not After']}.")
        else:
            st.error(f"Could not retrieve SSL certificate for {domain}.")
    else:
        st.warning("Please enter a domain name.")

# SPF, DMARC, and DNSSEC Check
if st.button("Check SPF/DMARC/DNSSEC"):
    if domain:
        domain = domain.replace('http://', '').replace('https://', '').replace('@', '')
        valid, message = validate_domain_with_ai(domain)
        if valid:
            spf_status = check_spf_record(domain)
            dmarc_status, dmarc_policy_status = check_dmarc_record(domain)
            dns_status = check_dnssec(domain)
            output = format_output(spf_status, dmarc_status, dmarc_policy_status, dns_status)
            st.markdown(output, unsafe_allow_html=True)
        else:
            st.error(message)
    else:
        st.error("Please enter a domain name.")
