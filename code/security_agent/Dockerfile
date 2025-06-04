# Use a slim and modern Python base image
FROM python:3.11-slim

# Install system tools required for MACsec and networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping tcpdump \
  && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Install required Python packages
RUN pip install --no-cache-dir \
    kafka-python \
    pyroute2

# Copy the security agent script into the container
COPY main.py .

# Define the default command to run the agent
CMD ["python", "main.py"]
