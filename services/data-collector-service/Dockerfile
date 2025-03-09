# Use an official Python 3 base image (slim to reduce size).
FROM python:3.9-slim

# Disable interactive apt
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies (tcpdump, libpcap-dev) for Scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
  && rm -rf /var/lib/apt/lists/*

# Create directories in the container:
#   /src    for your Python source
#   /config for your config files
#   /data   so that ../data from /src is valid
RUN mkdir -p /src /config /data

# Set /src as the working directory
WORKDIR /src

# Copy requirements into /src, then install them
COPY requirements.txt /src/
RUN pip install --no-cache-dir -r requirements.txt

# Copy your Python script(s) from src/ on the host into /src in the container
COPY src/ /src/

# Copy config files (daemon_config.ini, etc.) into /config
COPY config/ /config/

# Optionally, if you have initial data in project-root/data you want in the image:
# COPY data/ /data/

# Default command (bash), you can override with:
#   docker run ... python data-collector-server.py start ...
CMD ["/bin/bash"]


