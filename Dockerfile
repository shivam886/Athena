# Use Python as base image
FROM python:3.11

# Set working directory inside the container
WORKDIR /app

# Copy all necessary files
COPY . /app

# Install necessary packages
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y git

# Clone the huntkit repository
RUN git clone https://github.com/mcnamee/huntkit.git

# Install huntkit dependencies
WORKDIR /app/huntkit
RUN pip install -r requirements.txt
WORKDIR /app

# Expose the port for Streamlit
EXPOSE 8501

# Command to run Streamlit
CMD ["streamlit", "run", "Web_app_testing.py"]
