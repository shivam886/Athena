import streamlit as st
import subprocess
import os

# Function to run huntkit scanner
def run_huntkit_scan(target_url):
    try:
        # Navigate to the huntkit directory
        os.chdir("/app/huntkit")  # Make sure this is the correct path inside the container

        # Command to run the huntkit scan
        scan_command = f"python3 huntkit.py scan -u {target_url}"
        result = subprocess.run(scan_command, shell=True, capture_output=True, text=True)

        # Go back to the root app directory (if needed)
        os.chdir("/app")  # Ensure to navigate back

        return result.stdout
    except Exception as e:
        return str(e)

# Streamlit Frontend
def main():
    st.title('Website Vulnerability Scanner using HuntKit')
    
    target_url = st.text_input('Enter the target URL:', 'http://example.com')

    if st.button('Start Scan'):
        with st.spinner('Scanning...'):
            scan_results = run_huntkit_scan(target_url)
            st.success('Scan Complete!')
            st.write(scan_results)

if __name__ == "__main__":
    main()
