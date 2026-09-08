# ==============================================================================
# Dockerfile: eBPF Linux Threat Detection & EDR Agent Container
# ==============================================================================
# Privileged container runtime equipped with Linux kernel tracing dependencies,
# Clang/LLVM compiler toolchain, BCC (BPF Compiler Collection), and Python agent.
# ==============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies, Linux kernel build headers, and BCC
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    make \
    gcc \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    python3-bpfcc \
    linux-headers-generic \
    python3 \
    python3-pip \
    python3-dev \
    libelf-dev \
    libz-dev \
    pkg-config \
    netcat-openbsd \
    iproute2 \
    procps \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/ebpf-edr-agent

# Copy dependency files first for layer caching
COPY requirements.txt .
COPY agent/requirements.txt ./agent/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy entire repository
COPY . .

# Grant execute permissions to simulation scripts
RUN chmod +x simulations/*.sh

# Pre-compile C simulation binaries
RUN if [ -f simulations/trigger_ptrace.c ]; then \
        gcc -O2 simulations/trigger_ptrace.c -o simulations/trigger_ptrace; \
    fi

# Default environment variables
ENV EDR_RULES_DIR=/opt/ebpf-edr-agent/rules
ENV EDR_BPF_DIR=/opt/ebpf-edr-agent/bpf
ENV EDR_ALERT_LOG=/var/log/edr_alerts.json

# Expose alert log volume mount point
VOLUME ["/var/log"]

# Set agent entrypoint
ENTRYPOINT ["python3", "-m", "agent.main"]
CMD ["--rules-dir", "/opt/ebpf-edr-agent/rules", "--bpf-dir", "/opt/ebpf-edr-agent/bpf", "--alert-file", "/var/log/edr_alerts.json"]
