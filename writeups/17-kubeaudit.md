# Scenario 17: KubeAudit - Audit Kubernetes Clusters

## Overview

This scenario shifts from offensive exploitation to defensive auditing. After learning how to exploit Kubernetes misconfigurations in previous scenarios, we now use `kubeaudit` - an open-source tool by Shopify - to proactively detect these same vulnerabilities before attackers do. Security auditing is essential for compliance, risk management, and maintaining a strong security posture.

## Tool Introduction

**KubeAudit** is a command-line tool and Go package that audits Kubernetes clusters for common security concerns:

| Check Category | What It Detects |
|----------------|-----------------|
| **Privileged** | Containers running in privileged mode |
| **RunAsNonRoot** | Containers running as root user |
| **ReadOnlyRootFilesystem** | Writable container filesystems |
| **Capabilities** | Dangerous Linux capabilities added |
| **HostNamespaces** | Pods sharing host PID/IPC/Network |
| **Mounts** | Sensitive host paths mounted |
| **NetPolicies** | Missing network policies |
| **AppArmor/Seccomp** | Missing security profiles |
| **Automount** | ServiceAccount tokens auto-mounted |

## Attack Walkthrough

### Step 1: Deploy Audit Pod with Elevated Privileges

To audit the entire cluster, we need a pod with cluster-admin level permissions. Spawned a hacker container with the `superadmin` ServiceAccount:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubeaudit-scanner
  namespace: kube-system
spec:
  serviceAccountName: superadmin
  containers:
  - name: kubeaudit-scanner
    image: madhuakula/hacker-container
    command: ["sleep", "3600"]
  restartPolicy: Never
```

**Note**: The scenario documentation references a `tiller` ServiceAccount (from Helm v2), but this cluster uses `superadmin` instead.

### Step 2: Run Full Cluster Audit

Executed kubeaudit in cluster mode to scan all resources:

```bash
kubeaudit all
```

When running inside a cluster, kubeaudit automatically:
1. Detects it's in a Kubernetes environment
2. Uses the mounted ServiceAccount token
3. Scans all accessible namespaces and resources

### Step 3: Analyze Findings

The audit revealed **194+ security issues** across the intentionally vulnerable cluster:

## Audit Results Summary

### Critical Findings (Errors)

| Count | Finding | Severity | Risk |
|-------|---------|----------|------|
| 4 | **PrivilegedTrue** | Critical | Full host access, container escape |
| 3 | **NamespaceHostPIDTrue** | Critical | Host process visibility, escape vector |
| 3 | **NamespaceHostNetworkTrue** | Critical | Network sniffing, bypass network policies |
| 5 | **SensitivePathsMounted** | Critical | Docker socket, /etc access |
| 2 | **NamespaceHostIPCTrue** | Critical | Host IPC namespace access |
| 1 | **AllowPrivilegeEscalationTrue** | Critical | Explicit privilege escalation enabled |

### Common Misconfigurations (Warnings)

| Count | Finding | Impact |
|-------|---------|--------|
| 20 | AppArmorAnnotationMissing | No AppArmor confinement |
| 19 | SeccompAnnotationMissing | No syscall filtering |
| 19 | RunAsNonRootPSCNilCSCNil | Container runs as root |
| 19 | ReadOnlyRootFilesystemNil | Writable filesystem (malware persistence) |
| 18 | AllowPrivilegeEscalationNil | Privilege escalation not denied |
| 17 | CapabilityOrSecurityContextMissing | No security context defined |
| 13 | AutomountServiceAccountTokenTrueAndDefaultSA | Default SA token exposed |
| 7 | MissingDefaultDenyIngressAndEgressNetworkPolicy | No network segmentation |

### Mapping to Previous Exploits

The audit findings directly correspond to vulnerabilities we exploited:

| Kubeaudit Finding | Scenario | Attack Performed |
|-------------------|----------|------------------|
| `PrivilegedTrue` + `HostPIDTrue` | #4 Container Escape | Escaped to host via nsenter |
| `SensitivePathsMounted` (docker.sock) | #2 DIND | Spawned host containers |
| `MissingNetworkPolicy` | #11 Namespace Bypass | Cross-namespace Redis access |
| `AutomountServiceAccountToken` | #16 RBAC | Used SA token to read secrets |

## Understanding Severity Levels

### Error vs Warning

| Level | Meaning | Example |
|-------|---------|---------|
| **Error** | Explicit dangerous configuration | `privileged: true` |
| **Warning** | Missing security hardening | `privileged` not explicitly set to `false` |

**Why does `PrivilegedNil` show as warning?**
- When `privileged` is not set, Kubernetes defaults to `false`
- However, security best practice requires **explicit** `privileged: false`
- Defense-in-depth: explicit settings prevent accidental changes

## Key Lessons

### 1. Audit Modes

Kubeaudit supports multiple modes:

| Mode | Use Case | Command |
|------|----------|---------|
| **Cluster** | Running inside cluster with SA token | `kubeaudit all` |
| **Local** | With kubeconfig file | `kubeaudit all -c ~/.kube/config` |
| **Manifest** | Scanning YAML files pre-deployment | `kubeaudit all -f deployment.yaml` |

### 2. Selective Auditing

Run specific audits instead of all:

```bash
# Check only privileged containers
kubeaudit privileged

# Check only capabilities
kubeaudit capabilities

# Check only network policies
kubeaudit netpols

# Check only sensitive mounts
kubeaudit mounts
```

### 3. Priority Remediation

Based on audit results, prioritize fixes:

| Priority | Finding Type | Why |
|----------|--------------|-----|
| P0 (Critical) | PrivilegedTrue, HostPID, HostNetwork | Direct container escape paths |
| P0 (Critical) | SensitivePathsMounted (docker.sock) | Full cluster compromise |
| P1 (High) | AutomountServiceAccountToken | Credential theft |
| P2 (Medium) | RunAsRoot | Exploit amplification |
| P3 (Low) | Missing AppArmor/Seccomp | Defense-in-depth |

## Remediation Examples

### Fix Privileged Container

```yaml
# BEFORE (vulnerable)
spec:
  containers:
  - name: app
    securityContext:
      privileged: true

# AFTER (secure)
spec:
  containers:
  - name: app
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

### Add Default-Deny Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Disable ServiceAccount Token Automount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
automountServiceAccountToken: false
```

## Integration with CI/CD

Shift-left by scanning manifests before deployment:

```yaml
# GitLab CI example
security-audit:
  stage: test
  script:
    - kubeaudit all -f k8s/deployment.yaml --exitcode 2
  allow_failure: false
```

```yaml
# GitHub Actions example
- name: Kubeaudit Scan
  run: |
    kubeaudit all -f manifests/ --exitcode 2
```

## Comparison with Other Tools

| Tool | Focus | Output |
|------|-------|--------|
| **kubeaudit** | Pod/container security context | CLI, JSON |
| **kube-bench** | CIS Benchmark compliance (node-level) | CLI, JSON |
| **Popeye** | Resource sanitization, best practices | CLI, HTML |
| **Trivy** | Vulnerabilities, misconfigs, secrets | CLI, SARIF |
| **Falco** | Runtime detection (not static) | Alerts |

## MITRE ATT&CK Relevance

Kubeaudit detects configurations that enable these techniques:

| Technique | ID | Kubeaudit Check |
|-----------|-----|-----------------|
| Escape to Host | T1611 | privileged, hostPID, hostNetwork |
| Container Administration Command | T1609 | mounts (docker.sock) |
| Unsecured Credentials | T1552 | automount, mounts |
| Network Service Discovery | T1046 | netpols (missing policies) |

## OWASP Kubernetes Top 10 Alignment

| Risk | Kubeaudit Coverage |
|------|-------------------|
| **K01: Insecure Workload Configurations** | privileged, runAsRoot, capabilities |
| **K02: Supply Chain Vulnerabilities** | (use Trivy for image scanning) |
| **K03: Overly Permissive RBAC** | (use rbac-tool for RBAC) |
| **K04: Lack of Network Segmentation** | netpols |
| **K06: Broken Authentication** | automount |

## Commands Reference

```bash
# Full cluster audit
kubeaudit all

# Audit with kubeconfig
kubeaudit all -c /path/to/kubeconfig

# Audit specific namespace
kubeaudit all -n default

# Audit manifest files (pre-deployment)
kubeaudit all -f deployment.yaml
kubeaudit all -f ./manifests/

# Specific checks
kubeaudit privileged
kubeaudit capabilities
kubeaudit netpols
kubeaudit mounts
kubeaudit nonroot
kubeaudit rootfs
kubeaudit automountServiceAccountToken

# Output as JSON for processing
kubeaudit all -o json | jq '.[] | select(.AuditResultName == "PrivilegedTrue")'

# Exit with error code (for CI/CD)
kubeaudit all --exitcode 2
```

## References

- [KubeAudit GitHub](https://github.com/Shopify/kubeaudit)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
