import json
import re
import virustotal_python
from base64 import urlsafe_b64encode
import argparse
import streamlit as st
import requests
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt

# Function to check URL using VirusTotal API
def check_url_virustotal(url, api_key):
    with virustotal_python.Virustotal(api_key) as vtotal:
        try:
            # Submitting URL for analysis
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # Getting report
            report = vtotal.request(f"urls/{url_id}")
            final_data = report.data
            final_string_data = json.dumps(final_data)
            
            # Extracting and analyzing data
            pattern = re.compile(r'"(malicious|suspicious)": (\d+)')
            matches = pattern.findall(final_string_data)
            
            results = {match[0]: int(match[1]) for match in matches}
            return results
        except virustotal_python.VirustotalError as err:
            st.error(f"Failed to send URL: {url} for analysis and get the report: {err}")
            return None

# Function to check for suspicious URL characteristics
def is_suspicious_url(url):
    ip_pattern = re.compile(r'^(http[s]?://)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)')
    if ip_pattern.search(url):
        return True

    if len(url) > 75:
        return True

    suspicious_keywords = ["login", "verify", "update", "security", "ebayisapi", "banking", "secure"]
    if any(keyword.lower() in url.lower() for keyword in suspicious_keywords):
        return True

    return False

# Function to fetch page content
def fetch_page_content(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        st.error(f"Error fetching URL {url}: {e}")
        return None

# Function to check for suspicious content in the page
def is_suspicious_content(content):
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        form_text = form.text.lower()
        form_action = form.get('action', '').lower()
        if any(keyword in form_text for keyword in ["password", "ssn", "credit card", "bank account"]) or \
           any(keyword in form_action for keyword in ["login", "secure", "verify"]):
            return True

    suspicious_keywords = ["login", "verify", "update", "secure", "confirm", "account"]
    keyword_count = sum(content.lower().count(keyword) for keyword in suspicious_keywords)

    if keyword_count > 10:
        return True

    return False

# Function to scan URL using custom logic
def scan_url(url):
    if is_suspicious_url(url):
        return True

    content = fetch_page_content(url)
    if content and is_suspicious_content(content):
        return True

    return False

# Streamlit Application
st.set_page_config(page_title="URL Scanner", page_icon="🔍")
st.title("Phishing Scanner")

st.write("This is a simple Streamlit app for checking whether a URL is a *Phishing link* or not.")

with st.expander("Rules:"):
    st.write("You can create interactive widgets like sliders and text inputs:")

st.header("Data Display")

text = st.text_input("Please enter a URL to scan: ")
user_url = text.strip()
if user_url:
    with st.spinner("Scanning URL..."):
      
        api_key = "<<replace with your key>>"
        
        # Checking URL with VirusTotal
        vt_results = check_url_virustotal(user_url, api_key)
        
        # Scanning URL with custom logic
        custom_result = scan_url(user_url)
        
        if vt_results:
            st.write("*VirusTotal Report*")
            for key, value in vt_results.items():
                st.write(f"{key.capitalize()}: {value}")
                if value > 0:
                    st.write("*Warning: This is a phishing URL*")
                    
            # Plotting line graph for VirusTotal results
            labels = list(vt_results.keys())
            values = list(vt_results.values())
            plt.figure(figsize=(10, 6))
            plt.plot(labels, values, marker='o', linestyle='-', color='blue')
            plt.xlabel('Type')
            plt.ylabel('Count')
            plt.title('Phishing URL Detection - Line Graph')
            st.pyplot(plt)
        
        # Displaying custom scan result
        st.write("*Custom Scan Result*")
        if custom_result:
            st.write("Warning: URL or page content is suspicious.")
        else:
            st.write("URL seems to be safe.")
else:
    st.write("Please enter a URL to scan.")
