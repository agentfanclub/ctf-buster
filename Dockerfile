# =============================================================================
# ctf-buster Development Container
# Alternative to the Nix flake for VS Code dev containers.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build the Rust CLI
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    libdbus-1-dev \
    libssl-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

# Install Rust stable via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && \
    strip target/release/ctf

# ---------------------------------------------------------------------------
# Stage 2: Runtime image with all CTF tools
# ---------------------------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ---- System packages & security tools available via apt --------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials (needed for some pip packages)
    build-essential \
    ca-certificates \
    # Rust development (installed via rustup below)
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    # Python
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    # Binary analysis & reverse engineering
    radare2 \
    gdb \
    nasm \
    binutils \
    elfutils \
    patchelf \
    # Forensics
    binwalk \
    exiftool \
    file \
    foremost \
    steghide \
    xxd \
    testdisk \
    yara \
    # Networking
    netcat-openbsd \
    nmap \
    socat \
    tcpdump \
    curl \
    wget \
    # General utilities
    jq \
    strace \
    ltrace \
    rlwrap \
    git \
    unzip \
    sudo \
    # Libraries for Python packages (Pillow, opencv, etc.)
    libffi-dev \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libjpeg-dev \
    libpng-dev \
    libopencv-dev \
  && rm -rf /var/lib/apt/lists/*

# ---- Install Rust stable toolchain via rustup (for development) -----------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rust-src rust-analyzer clippy rustfmt

# ---- Python packages (matching flake.nix pythonEnv) -----------------------
RUN pip3 install --break-system-packages --no-cache-dir \
    # MCP server framework
    fastmcp \
    # Crypto (ctf_crypto server)
    sympy \
    z3-solver \
    gmpy2 \
    pycryptodome \
    # Binary exploitation (ctf_pwn server)
    pwntools \
    capstone \
    keystone-engine \
    unicorn \
    ROPGadget \
    ropper \
    angr \
    # Forensics (ctf_forensics server)
    numpy \
    Pillow \
    opencv-python-headless \
    scapy \
    # General CTF / scripting
    beautifulsoup4 \
    cryptography \
    requests \
    lxml \
    pefile \
    # Testing
    pytest \
    pytest-cov

# ---- Install Node.js and Claude Code ----------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    npm install -g @anthropic-ai/claude-code

# ---- Copy built CLI binary from builder stage -----------------------------
COPY --from=builder /build/target/release/ctf /usr/local/bin/ctf

# ---- Create non-root user -------------------------------------------------
ARG USERNAME=ctf
ARG USER_UID=1000
ARG USER_GID=1000

# Create user, handling cases where UID/GID already exist (e.g. Ubuntu's default user)
RUN if id -u ${USER_UID} >/dev/null 2>&1; then \
      existing=$(getent passwd ${USER_UID} | cut -d: -f1); \
      usermod -l ${USERNAME} -d /home/${USERNAME} -m "$existing"; \
      groupmod -n ${USERNAME} $(getent group ${USER_GID} | cut -d: -f1) 2>/dev/null || true; \
    else \
      groupadd --gid ${USER_GID} ${USERNAME} 2>/dev/null || true; \
      useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME}; \
    fi && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/${USERNAME} && \
    chmod 0440 /etc/sudoers.d/${USERNAME}

# Move Rust toolchain to the non-root user
RUN mv /root/.cargo /home/${USERNAME}/.cargo && \
    mv /root/.rustup /home/${USERNAME}/.rustup && \
    chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.cargo /home/${USERNAME}/.rustup

ENV PATH="/home/${USERNAME}/.cargo/bin:${PATH}"
ENV CARGO_HOME="/home/${USERNAME}/.cargo"
ENV RUSTUP_HOME="/home/${USERNAME}/.rustup"

# ---- Copy project source for development ----------------------------------
WORKDIR /workspace
COPY --chown=${USERNAME}:${USERNAME} . .

# Ensure target dir is writable without volume mounts
RUN mkdir -p /workspace/target && chown ${USERNAME}:${USERNAME} /workspace/target

USER ${USERNAME}

CMD ["bash"]
