import streamlit as st
import dns.resolver
import logging
import requests

# Set up logging
logging.basicConfig(filename='email_spoofing_check.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

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

def check_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return "Status Ok"
        return "Status Not Found"
    except Exception as e:
        logging.error(f"Error checking DNSSEC for {domain}: {e}")
        return "Status Not Found"

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

def validate_domain_with_ai(domain):
    # Placeholder function for AI domain validation
    # Here, you'd integrate your LLaMA 3 model or any other AI model
    # For simplicity, we'll use a basic validation check
    if not domain or '.' not in domain:
        return False, "Invalid domain format. Please enter a correct domain name."
    try:
        requests.get(f"http://{domain}")
        return True, ""
    except requests.exceptions.RequestException:
        return False, "Domain does not exist. Please enter a correct domain name."

st.title("Email Spoofing Protection Check")

st.markdown("**Please enter the domain name without 'http://' or '@'**")

domain = st.text_input("Enter domain name:")

if st.button("Check"):
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
