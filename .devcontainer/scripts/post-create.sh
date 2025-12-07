#!/bin/bash
# post-create.sh - Runs once after container creation
set -e

echo "=== Kubernetes Goat Dev Container: Post-Create Setup ==="

# =============================================
# Security: Validate environment
# =============================================
validate_environment() {
    echo "[SECURITY] Validating environment..."

    # Set explicit PATH to prevent injection
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    # Check for suspicious environment variables
    local suspicious_vars=("PROMPT" "PS1_OVERRIDE" "BASH_FUNC" "LD_PRELOAD" "LD_LIBRARY_PATH")
    for var in "${suspicious_vars[@]}"; do
        if printenv | grep -q "^${var}="; then
            echo "[WARNING] Suspicious environment variable detected: ${var}"
            unset "${var}" 2>/dev/null || true
        fi
    done
}

# =============================================
# Setup kubectl autocompletion
# =============================================
setup_kubectl_completion() {
    echo "[INFO] Setting up kubectl autocompletion..."
    kubectl completion bash > /etc/bash_completion.d/kubectl 2>/dev/null || true

    # Add to bashrc for vscode user
    cat >> /home/vscode/.bashrc << 'EOF'
source <(kubectl completion bash)
alias k=kubectl
complete -o default -F __start_kubectl k
EOF

    # Also for root
    cat >> /root/.bashrc << 'EOF'
source <(kubectl completion bash)
alias k=kubectl
complete -o default -F __start_kubectl k
EOF
}

# =============================================
# Setup helm autocompletion
# =============================================
setup_helm_completion() {
    echo "[INFO] Setting up helm autocompletion..."
    helm completion bash > /etc/bash_completion.d/helm 2>/dev/null || true
}

# =============================================
# Create security-hardened directories
# =============================================
setup_secure_directories() {
    echo "[SECURITY] Setting up secure directories..."

    mkdir -p /run/secrets
    chmod 700 /run/secrets
}

# =============================================
# Verify tool installations
# =============================================
verify_tools() {
    echo "[INFO] Verifying tool installations..."

    local tools=("kubectl" "helm" "git" "curl" "jq" "uv" "uvx" "claude")
    local failed=0

    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version
            case "$tool" in
                kubectl) version=$(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1) ;;
                helm) version=$(helm version --short 2>/dev/null) ;;
                uv) version=$(uv --version 2>/dev/null) ;;
                claude) version="installed" ;;
                *) version="installed" ;;
            esac
            echo "  [OK] $tool: $version"
        else
            echo "  [ERROR] $tool: NOT INSTALLED"
            failed=1
        fi
    done

    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        echo "  [OK] ANTHROPIC_API_KEY is set"
    else
        echo "  [INFO] ANTHROPIC_API_KEY not set (required for Claude Code)"
    fi

    return $failed
}

# =============================================
# Display helpful information
# =============================================
show_info() {
    echo ""
    echo "=========================================="
    echo " Kubernetes Goat Development Environment"
    echo "=========================================="
    echo ""
    echo "This container provides tools to work with Kubernetes Goat."
    echo "You need to connect kubectl to an external Kubernetes cluster."
    echo ""
    echo "Tools available:"
    echo "  - kubectl (alias: k)"
    echo "  - helm"
    echo "  - claude (Claude Code CLI)"
    echo "  - uvx"
    echo "  - gh (GitHub CLI)"
    echo ""
}

# =============================================
# Main execution
# =============================================
main() {
    validate_environment
    setup_kubectl_completion
    setup_helm_completion
    setup_secure_directories
    verify_tools || true
    show_info

    echo "=== Post-create setup complete ==="
}

main "$@"
