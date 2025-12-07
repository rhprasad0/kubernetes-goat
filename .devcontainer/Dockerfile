# Kubernetes Goat Development Container
# Ubuntu 22.04 with kubectl, helm, Claude Code, and uvx

FROM ubuntu:22.04

# Avoid prompts during package installation
ARG DEBIAN_FRONTEND=noninteractive

# ============================================
# SECTION 1: System packages and dependencies
# ============================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential tools
    ca-certificates \
    curl \
    wget \
    git \
    gnupg \
    lsb-release \
    software-properties-common \
    # Container runtime dependencies
    iptables \
    iproute2 \
    procps \
    kmod \
    # Build essentials for native extensions
    build-essential \
    # JSON processing
    jq \
    # Network tools (for debugging)
    dnsutils \
    netcat-openbsd \
    iputils-ping \
    # Editors
    vim \
    nano \
    # Process management
    supervisor \
    # Bash completion
    bash-completion \
    # sudo for user operations
    sudo \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# SECTION 2: Install kubectl
# ============================================
RUN curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | \
    gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
    chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | \
    tee /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update && apt-get install -y kubectl && \
    rm -rf /var/lib/apt/lists/*

# ============================================
# SECTION 3: Install Helm
# ============================================
RUN curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ============================================
# SECTION 4: Install uv (Python package manager) and uvx
# ============================================
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv && \
    mv /root/.local/bin/uvx /usr/local/bin/uvx

# ============================================
# SECTION 5: Install Node.js 20 (for Claude Code CLI)
# ============================================
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ============================================
# SECTION 6: Install Claude Code CLI
# ============================================
RUN npm install -g @anthropic-ai/claude-code

# ============================================
# SECTION 7: Create non-root user for development
# ============================================
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME && \
    echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

# ============================================
# SECTION 8: Copy scripts
# ============================================
COPY scripts/ /opt/devcontainer-scripts/
RUN chmod +x /opt/devcontainer-scripts/*.sh

# ============================================
# SECTION 9: Environment setup
# ============================================
ENV PATH="/usr/local/bin:${PATH}"

USER vscode

WORKDIR /workspaces/kubernetes-goat

CMD ["/bin/bash"]
