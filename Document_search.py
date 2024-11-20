import streamlit as st
import requests

# Google API details
API_KEY = "AIzaSyA0t2vtCRGPcUrGWoCXE4epBGpqbgmbb60"
SEARCH_ENGINE_ID = "60bbab66bd5d84f01"

# Google Dork templates for documents, generalized for broader searches
dork_templates = 'filetype:pdf "{keyword}" or filetype:doc "{keyword}" or filetype:docx "{keyword}" or filetype:xls "{keyword}" or filetype:xlsx "{keyword}" or filetype:csv "{keyword}" or filetype:txt "{keyword}" or "{keyword}" ext:pdf or "{keyword}" ext:doc or "{keyword}" ext:docx or "{keyword}" ext:xls or "{keyword}" ext:xlsx or "{keyword}" ext:csv or "{keyword}" ext:txt'


# Function to perform Google Search using Google Custom Search API
def google_dork_search(query):
    try:
        # Set up the API URL
        api_url = f"https://www.googleapis.com/customsearch/v1?key={API_KEY}&cx={SEARCH_ENGINE_ID}&q={query}"
        
        # Make the request to the API
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an error for bad responses
        results = response.json()
        
        # Return the list of search results
        return results.get('items', [])
    
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return []

# Streamlit Frontend
def main():
    st.title("Document Search")

    # Input field for keyword
    keyword = st.text_input("Enter a name, company, or keyword to search for documents:")

    if st.button("Search"):
        if keyword:
            with st.spinner('Searching...'):
                results = []
                # Loop over all predefined dork templates
                for dork_template in dork_templates:
                    search_query = dork_template.format(keyword=keyword)
                    query_results = google_dork_search(search_query)
                    results.extend(query_results)  # Collect results from all dork queries
                
                # Show the search results
                if results:
                    st.success(f"Search results for '{keyword}':")
                    for index, result in enumerate(results, start=1):
                        st.write(f"{index}. [{result['title']}]({result['link']})")
                else:
                    st.warning(f"No documents found for '{keyword}'.")
        else:
            st.warning("Please enter a search keyword.")

if __name__ == "__main__":
    main()
