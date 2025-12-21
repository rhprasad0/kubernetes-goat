# Scenario 18: Falco - Runtime Security Monitoring & Detection

## Overview

This scenario introduces **Falco**, a CNCF open-source runtime security tool that detects anomalous activity in containers and Kubernetes clusters. Unlike static analysis tools (kubeaudit, kube-bench) that find misconfigurations before deployment, Falco monitors live system calls to catch active attacks in real-time.

We also deployed **canary tokens** as an additional detection layer, testing a defense-in-depth approach to intrusion detection.

## Tool Introduction

**Falco** operates at the kernel level using eBPF (extended Berkeley Packet Filter) to monitor syscalls - the interface between applications and the Linux kernel:

| Detection Layer | What It Monitors |
|-----------------|------------------|
| **File Access** | Reads/writes to sensitive files (/etc/shadow, /etc/passwd) |
| **Process Execution** | Shell spawns, unexpected binaries |
| **Network Activity** | Reverse shells, unexpected connections |
| **Container Escapes** | Namespace changes, privileged operations |
| **Credential Access** | Reading service account tokens, secrets |

### Falco vs Canary Tokens

| Mechanism | Detection Type | Network Required | Alerts On |
|-----------|----------------|------------------|-----------|
| **Falco** | Passive (syscall monitoring) | No | File read, process spawn, etc. |
| **Canary Tokens** | Active (callback-based) | Yes (egress) | Credential usage, file open |

## Setup Walkthrough

### Step 1: Deploy Falco via Helm

```bash
# Add Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with modern eBPF driver (no kernel headers needed)
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true
```

Verified Falco initialized correctly:
```
Falco version: 0.42.1 (x86_64)
Loading rules from: /etc/falco/falco_rules.yaml
Opening 'syscall' source with modern BPF probe.
```

### Step 2: Deploy Canary Tokens

Created honeypot files designed to look like legitimate credentials:

| Canary File | Placement | Why Attackers Look Here |
|-------------|-----------|------------------------|
| AWS credentials | `/root/.aws/credentials` | Standard AWS CLI credential path |
| Kubeconfig | `/root/.kube/config` | Kubernetes credential file |
| passwords.xlsx | `/tmp/passwords.xlsx` | Obvious bait in common temp dir |

Deployed to both target pods:
```bash
# system-monitor pod (container escape scenario)
kubectl cp aws_api_key.txt default/system-monitor-xxx:/root/.aws/credentials
kubectl cp kubeconfig default/system-monitor-xxx:/root/.kube/config
kubectl cp passwords.xlsx default/system-monitor-xxx:/tmp/passwords.xlsx

# health-check pod (DIND scenario)
kubectl cp aws_api_key.txt default/health-check-xxx:/root/.aws/credentials
kubectl cp kubeconfig default/health-check-xxx:/root/.kube/config
kubectl cp passwords.xlsx default/health-check-xxx:/tmp/passwords.xlsx
```

**Canary Token Format** - AWS credentials were properly formatted to avoid detection as fake:
```ini
[default]
aws_access_key_id = AKIA[REDACTED]
aws_secret_access_key = [REDACTED]
output = json
region = us-east-2
```
*Note: Actual canary tokens from canarytokens.org - values redacted. The `AKIA` prefix is correct for AWS access keys, making the honeypot convincing.*

### Step 3: Monitor for Attacks

Started real-time Falco log monitoring:
```bash
kubectl logs -f -n falco -l app.kubernetes.io/name=falco -c falco
```

## Attack Detection Results

### PentestGPT Attack on health-check Pod

Launched an AI-driven attack tool (PentestGPT) against the health-check pod to test detection capabilities.

**Falco Alerts Generated:**

| Time | Alert | Details |
|------|-------|---------|
| 21:48:55 | Sensitive file opened | `/etc/pam.d/*` (multiple auth files) |
| 21:48:55 | Sensitive file opened | `/etc/pam.conf` |
| 21:48:56 | Sensitive file opened | `/etc/shadow` |

**Attack Pattern Detected:**
```
command=grep -r k8s_goat{ /
```

PentestGPT used recursive grep to search the entire filesystem for the CTF flag pattern. This touched authentication-related files, triggering Falco's sensitive file access rules.

### Canary Token Results

| Detection Layer | Result | Reason |
|-----------------|--------|--------|
| Falco | Fired | Detected syscalls locally - no network needed |
| Canary Tokens | Silent | PentestGPT container blocked egress; tokens couldn't "phone home" |

**Key Finding**: Canary tokens require outbound network access to alert. If an attacker (or their tooling) restricts egress, callback-based canaries fail silently.

## Key Lessons

### 1. Defense in Depth - Multiple Detection Layers

| Layer | Detects | Limitation |
|-------|---------|------------|
| **Falco** | All syscall-level activity | Requires deployment, rule tuning |
| **Canary Tokens** | Credential usage/exfiltration | Requires network egress |
| **Network Policies** | Lateral movement | Doesn't see container internals |
| **Audit Logs** | API server activity | Doesn't see container activity |

No single tool catches everything - layer defenses.

### 2. Falco's Kernel-Level Visibility

Falco sees everything because it hooks into the kernel via eBPF:
- **No network required** - works in air-gapped environments
- **No container cooperation** - attacker can't disable it from inside
- **Full visibility** - sees all file access, process spawns, network calls

### 3. Canary Token Limitations

Traditional canary tokens (canarytokens.org) require:
1. Attacker to actually **use** the credential (not just read it)
2. Outbound network access to callback server
3. No canary detection/avoidance by attacker

**Alternative approaches for restricted environments:**
- Custom Falco rules for honeypot files
- File access audit logging (auditd)
- SIEM integration with local log collection

### 4. Attack Pattern Recognition

The Falco alerts revealed PentestGPT's methodology:
1. Recursive filesystem search for known patterns
2. Touched sensitive files during enumeration
3. Running as root inside container

This matches real-world attacker behavior - automated credential harvesting.

## Falco Rules Reference

### Default Rules Triggered

| Rule | Triggers On |
|------|-------------|
| `Read sensitive file untrusted` | /etc/shadow, /etc/passwd, etc. |
| `Redirect stdout/stdin to network` | Reverse shell patterns |
| `Shell spawned in container` | Interactive shell access |

### Custom Rule Example (Canary Detection)

To detect access to planted canary files without network callbacks:

```yaml
- rule: Canary File Accessed
  desc: Detect access to honeypot credential files
  condition: >
    open_read and
    container and
    (fd.name = "/root/.aws/credentials" or
     fd.name = "/root/.kube/config" or
     fd.name = "/tmp/passwords.xlsx")
  output: >
    Canary file accessed (file=%fd.name user=%user.name
    container=%container.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [canary, honeypot, credential_access]
```

## Integration with SOC/SIEM

Falco outputs can be forwarded to security infrastructure:

| Destination | Method |
|-------------|--------|
| **Slack/Teams** | Falcosidekick |
| **SIEM (Splunk, Elastic)** | JSON output + log shipper |
| **AWS CloudWatch** | Falcosidekick |
| **PagerDuty** | Falcosidekick alerts |

```bash
# Enable Falcosidekick for alert forwarding
helm upgrade falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://..."
```

## MITRE ATT&CK Coverage

| Technique | ID | Falco Detection |
|-----------|-----|-----------------|
| Credential Dumping | T1003 | Read sensitive file rules |
| Container Escape | T1611 | Namespace/privilege changes |
| Command & Scripting | T1059 | Shell spawn detection |
| Account Discovery | T1087 | /etc/passwd, /etc/shadow access |
| File and Directory Discovery | T1083 | Sensitive path enumeration |

## Commands Reference

```bash
# Install Falco
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf

# View real-time alerts
kubectl logs -f -n falco -l app.kubernetes.io/name=falco -c falco

# Check Falco pod status
kubectl get pods -n falco

# View loaded rules
kubectl exec -n falco <falco-pod> -c falco -- cat /etc/falco/falco_rules.yaml

# Uninstall Falco
helm uninstall falco -n falco
```

## References

- [Falco Official Documentation](https://falco.org/docs/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick)
- [eBPF and Falco](https://falco.org/blog/choosing-a-driver/)
- [Canary Tokens](https://canarytokens.org)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
