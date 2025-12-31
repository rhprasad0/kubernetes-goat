# Scenario 21: Cilium Tetragon - eBPF-based Security Observability

## Overview

This scenario explores **Cilium Tetragon**, an eBPF-based runtime security tool that provides deep kernel-level observability into Kubernetes workloads. Unlike application-level logging, Tetragon monitors system calls directly in the kernel, making it impossible for attackers to evade detection.

## Why Kernel-Level Monitoring Matters

Traditional application logs are easy to evade:
- Attackers can delete or modify log files
- Logging processes can be killed
- Exploits can bypass the application layer entirely

**eBPF (extended Berkeley Packet Filter)** solves this by hooking directly into the Linux kernel. Every action on a system must go through system calls (syscalls):

| Action | Syscall |
|--------|---------|
| Read a file | `open()`, `read()` |
| Execute a binary | `execve()` |
| Open a network connection | `socket()`, `connect()` |
| Spawn a process | `fork()`, `clone()` |

Tetragon captures these syscalls at the kernel level - the only way to evade it is to compromise the kernel itself.

## Installation

Deployed Tetragon using Helm:

```bash
# Add Cilium Helm repository
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon
kubectl create namespace tetragon
helm install tetragon cilium/tetragon -n tetragon --wait
```

### Verification

```bash
kubectl get pods -n tetragon
```

| Pod | Role |
|-----|------|
| `tetragon-operator-*` | Manages TracingPolicies and CRDs |
| `tetragon-*` (DaemonSet) | eBPF agent running on each node |

## Architecture

```
+---------------------------------------------+
|              Kubernetes Node                |
|  +---------------------------------------+  |
|  |            Linux Kernel               |  |
|  |  +--------------------------------+   |  |
|  |  |   eBPF Programs (Tetragon)     |   |  |
|  |  |  Monitoring: execve, open,     |   |  |
|  |  |  connect, write, etc.          |   |  |
|  |  +--------------------------------+   |  |
|  +---------------------------------------+  |
|                     ^                       |
|                     | syscalls              |
|  +---------+  +---------+  +---------+     |
|  |  Pod A  |  |  Pod B  |  |  Pod C  |     |
|  +---------+  +---------+  +---------+     |
+---------------------------------------------+
```

## Live Attack Detection

### Test Setup

Exposed `system-monitor-deployment` via port-forward and unleashed **PentestGPT** (autonomous AI attack agent) to exploit the SSRF/command injection vulnerability.

```bash
kubectl port-forward deployment/system-monitor-deployment 9090:8080 --address 0.0.0.0
```

### Viewing Tetragon Events

```bash
# Stream all process executions
kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon -c export-stdout -f | jq

# Filter to specific namespace
kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon -c export-stdout -f | \
  jq 'select(.process_exec.process.pod.namespace == "default")'

# Compact view
kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon -c export-stdout -f | \
  jq -r '[.process_exec.process.binary, .process_exec.process.pod.name, .process_exec.process.arguments] | @tsv'
```

### Attack Activity Captured

PentestGPT exploited the `health-check-deployment` pod via SSRF command injection. Tetragon captured every malicious command:

| Time | Command | Attack Technique |
|------|---------|------------------|
| 23:26:07 | `grep -r 'webhook\|vault' /etc/` | Credential hunting in config files |
| 23:26:31 | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` + `curl https://kubernetes.default/api/v1/...` | K8s API access with stolen SA token |
| 23:26:36 | `cat /proc/self/environ \| grep -i secret` | Environment variable exfiltration |

### Sample Tetragon Event (Formatted)

```json
{
  "process_exec": {
    "process": {
      "binary": "/usr/bin/sh",
      "arguments": "-c \"ping -c 2 127.0.0.1;TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api/v1/namespaces/default/serviceaccounts\"",
      "pod": {
        "namespace": "default",
        "name": "health-check-deployment-658869cbb5-zgdmd",
        "container": {
          "name": "health-check",
          "image": "madhuakula/k8s-goat-health-check:latest",
          "security_context": {"privileged": true}
        }
      },
      "uid": 0
    }
  },
  "time": "2025-12-31T23:26:31.362Z"
}
```

## Key Security Insights

### 1. Privileged Container Visibility
Every Tetragon event includes `security_context`, immediately flagging privileged containers - a critical indicator of potential container escape capability.

### 2. Command Injection Detection
The attack leveraged health-check's ping functionality to inject shell commands (`;` after `127.0.0.1`). Tetragon captured the full command including the injected payload - web application logs would only show "ping 127.0.0.1".

### 3. Service Account Token Theft
PentestGPT grabbed the SA token from `/var/run/secrets/kubernetes.io/serviceaccount/token` and attempted to enumerate K8s resources. Tetragon recorded:
- The `cat` reading the token file
- The `curl` command with the Authorization header
- The target URL revealing reconnaissance intent

### 4. Process Lineage
Tetragon tracks parent-child relationships, enabling reconstruction of attack chains:
```
systemd -> sh -> ping
                -> cat (token theft)
                -> curl (API enumeration)
```

## Tetragon vs Falco Comparison

| Capability | Tetragon | Falco |
|------------|----------|-------|
| Detection Method | eBPF | eBPF or kernel module |
| Default Scope | Process execution | Broad syscall coverage |
| Custom Rules | TracingPolicy CRDs | Falco Rules YAML |
| Enforcement | Can block syscalls | Detection only |
| Performance | Very low overhead | Low overhead |
| Kubernetes Integration | Native (CRDs) | Helm + sidecars |

**Key Difference**: Tetragon can **enforce** policies (block syscalls), not just detect. Falco is detection-only.

## TracingPolicy (Advanced)

Tetragon supports custom TracingPolicies for targeted monitoring:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-sensitive-file-access
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/etc/passwd"
```

This policy would generate events whenever `/etc/shadow` or `/etc/passwd` are accessed.

## MITRE ATT&CK Mapping

| Technique ID | Name | Detection |
|--------------|------|-----------|
| T1552.001 | Credentials in Files | `grep` for passwords, `cat` on credential files |
| T1078.001 | Valid Accounts (SA Token) | Access to serviceaccount token path |
| T1083 | File and Directory Discovery | Recursive file searches |
| T1059.004 | Unix Shell | Shell spawning with arguments |
| T1046 | Network Service Discovery | `curl` to internal services |

## Real-World Application

### SOC Integration
Tetragon events can be:
- Streamed to SIEM (Splunk, Elastic, etc.)
- Correlated with network telemetry
- Used for automated incident response

### Compliance
Kernel-level audit logs satisfy compliance requirements for:
- PCI-DSS (file integrity monitoring)
- SOC 2 (security event logging)
- HIPAA (access audit trails)

### CI/CD Security
Deploy TracingPolicies to:
- Detect unauthorized binary execution
- Alert on sensitive file access
- Block known attack patterns in runtime

## Key Takeaways

1. **Kernel-level visibility is essential** - Application logs can be evaded; syscall monitoring cannot
2. **eBPF is production-ready** - Low overhead, no kernel modules required
3. **Process genealogy matters** - Understanding parent-child relationships reveals attack chains
4. **Enforcement > Detection** - Tetragon can block attacks, not just log them
5. **Defense in depth** - Combine Tetragon with Falco, Network Policies, and admission controllers

## Tools Used

- **Cilium Tetragon 1.6.0** - eBPF-based security observability
- **Helm** - Kubernetes package manager
- **PentestGPT** - AI-powered penetration testing agent (attack generation)
- **jq** - JSON processing for log analysis
- **Claude Code** - AI assistant for analysis and documentation

## References

- [Tetragon Documentation](https://tetragon.io/docs/)
- [Cilium Security Observability](https://cilium.io/use-cases/security/)
- [eBPF.io - What is eBPF?](https://ebpf.io/)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

---

*Completed with guidance from Claude Code (Anthropic) - AI-assisted security analysis and documentation*
