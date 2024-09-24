import os
import pandas as pd
import streamlit as st
import whois
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== DOMAIN GENERATION FUNCTIONS ========== #
def generate_typos(original_domain):
    typos = set()
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    for i in range(len(original_domain)):
        # Substitute a character
        for c in alphabet:
            if original_domain[i] != c:
                typos.add(original_domain[:i] + c + original_domain[i+1:])
        # Delete a character
        typosquatting = original_domain[:i] + original_domain[i+1:]
        typos.add(typosquatting)
        # Insert a character
        for c in alphabet:
            typos.add(original_domain[:i] + c + original_domain[i:])
    return typos

def generate_combos(original_domain):
    prefixes = ['secure', 'my', 'get', 'the']
    suffixes = ['online', 'shop', 'store', 'app']
    combos = set()
    for prefix in prefixes:
        combos.add(prefix + original_domain)
    for suffix in suffixes:
        combos.add(original_domain + suffix)
    return combos

def generate_homographs(original_domain):
    homographs = set()
    replacements = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '@'}
    for char, replacement in replacements.items():
        homograph = original_domain.replace(char, replacement)
        homographs.add(homograph)
    return homographs

def generate_new_tlds(original_domain):
    tlds = ['.net', '.org', '.info', '.biz', '.co', '.io', '.tech']
    new_tlds = set()
    if '.' in original_domain:
        base = original_domain.split('.')[0]
    else:
        base = original_domain
    for tld in tlds:
        new_tlds.add(base + tld)
    return new_tlds

def generate_domain_variations(original_domain):
    variations = set()
    variations.update(generate_typos(original_domain))
    variations.update(generate_combos(original_domain))
    variations.update(generate_homographs(original_domain))
    variations.update(generate_new_tlds(original_domain))
    return variations

# ========== WHOIS & IP LOOKUP FUNCTION ========== #
def check_domain(domain):
    try:
        w = whois.whois(domain)
        # Resolve the IP address using socket
        ip_address = socket.gethostbyname(domain)
        return {
            'domain': domain,
            'ip_address': ip_address,
            'registered': True,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'registrant': w.registrant_name if hasattr(w, 'registrant_name') else None
        }
    except Exception as e:
        return {
            'domain': domain,
            'ip_address': None,
            'registered': False,
            'creation_date': None,
            'expiration_date': None,
            'registrant': None
        }

def check_domains_parallel(domains):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:  # Adjust max_workers based on your system
        futures = {executor.submit(check_domain, domain): domain for domain in domains}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                # Log the error if needed
                pass
    return results

# ========== STREAMLIT FRONTEND ========== #
st.title("Cyber Squatting Detection Tool")

# Step 1: Domain Name Input
original_domain = st.text_input('Enter the target domain (e.g., example.com)', 'example.com')

# Check if the user entered a domain and pressed enter
if original_domain:
    # Step 2: WHOIS Lookup for the genuine domain (includes IP address lookup)
    st.header("Genuine Domain Info")
    whois_info = check_domain(original_domain)
    df_whois = pd.DataFrame([whois_info])
    
    # Reformat dates for better display
    df_whois['creation_date'] = df_whois['creation_date'].apply(lambda x: str(x)[:10] if x else 'N/A')
    df_whois['expiration_date'] = df_whois['expiration_date'].apply(lambda x: str(x)[:10] if x else 'N/A')

    st.table(df_whois[['domain', 'ip_address', 'registered', 'creation_date', 'expiration_date', 'registrant']])

    # Step 3: Generate Domain Variations
    variations = generate_domain_variations(original_domain)

    # Step 4: WHOIS Lookup on Similar Domains (to check if they are registered/active with IP)
    st.header("Checking Similar Domain Availability")
    similar_domain_info = check_domains_parallel(variations)
    active_domains = [domain_info for domain_info in similar_domain_info if domain_info['registered']]

    # Add a column for Suspicious/Clean status (placeholder for future use)
    for domain in active_domains:
        # You can manually mark some domains as "Suspicious" for now or implement a check later
        domain['status'] = 'Suspicious' if 'hcltec' in domain['domain'] else 'Clean'

    # Step 5: Display active domains with WHOIS info and status
    if active_domains:
        df_active_domains = pd.DataFrame(active_domains)
        
        # Reformat dates for better display
        df_active_domains['creation_date'] = df_active_domains['creation_date'].apply(lambda x: str(x)[:10] if x else 'N/A')
        df_active_domains['expiration_date'] = df_active_domains['expiration_date'].apply(lambda x: str(x)[:10] if x else 'N/A')
        
        st.table(df_active_domains[['domain', 'ip_address', 'registered', 'creation_date', 'expiration_date', 'status']])
        
        # Display phishing/squatting domains
        st.header("Phishing & Squatting Domains Detected:")
        phishing_squatting_domains = df_active_domains[df_active_domains['status'] == 'Suspicious']
        st.table(phishing_squatting_domains[['domain', 'status']])
    else:
        st.write("No similar active domains were found.")
else:
    st.warning("Please enter a domain to start.")
