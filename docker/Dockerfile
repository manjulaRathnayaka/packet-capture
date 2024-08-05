FROM python:3.9-slim

# Install the necessary system dependencies for pypcap
RUN apt-get update && \
    apt-get install -y gcc libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Create a new user with a specific UID and GID
RUN groupadd -g 10001 appgroup && \
    useradd -m -u 10001 -g appgroup appuser

# Switch to the new user
USER 10001

# Set the working directory
WORKDIR /app

# Copy the application files
COPY --chown=appuser:appgroup capture.py /app/capture.py

# Install necessary Python packages
RUN pip install --user pypcap dpkt

# Run the application
CMD ["python", "/app/capture.py"]

