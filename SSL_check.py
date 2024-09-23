import streamlit as st
import ssl
import socket
from datetime import datetime
from dateutil import parser
import pytz
import logging

# Set up logging
logging.basicConfig(filename='ssl_check.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

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

st.title("SSL Certificate Expiry Information")

domain = st.text_input("Enter domain name:")
if st.button("Check"):
    if domain:
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
