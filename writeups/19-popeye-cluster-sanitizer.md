# Scenario 19: Popeye - Kubernetes Cluster Sanitizer

## Overview

This scenario introduces **Popeye**, a Kubernetes cluster sanitizer that scans live cluster resources and reports potential issues with deployed configurations. Unlike static analysis tools that scan YAML manifests on disk, Popeye examines what's **actually running** in your cluster - catching configuration drift, orphaned resources, and security misconfigurations.

## Tool Introduction

**Popeye** performs health checks against Kubernetes resources to ensure best practices are followed:

| Linter Category | What It Checks |
|-----------------|----------------|
| **Pods** | Resource limits, probes, security context, image tags |
| **Deployments** | Replica counts, update strategy, pod template issues |
| **Services** | Endpoint availability, port naming, selector matches |
| **ServiceAccounts** | Unused accounts, token automount settings |
| **ConfigMaps/Secrets** | Orphaned resources, unused references |
| **RBAC** | ClusterRoles, RoleBindings, permission scope |
| **Network Policies** | Missing ingress/egress rules |
| **Nodes** | Resource pressure, conditions |

### Popeye vs Other Audit Tools

| Tool | Analysis Type | Data Source | Best For |
|------|---------------|-------------|----------|
| **Popeye** | Live cluster | Kubernetes API | Configuration hygiene, drift detection |
| **KubeAudit** | Static/Live | Manifests or API | Security-focused auditing |
| **Kube-bench** | Live cluster | Node configuration | CIS benchmark compliance |
| **Trivy** | Static | Container images | Vulnerability scanning |

## Setup Walkthrough

### Step 1: Deploy Audit Pod with Elevated Privileges

Popeye requires cluster-wide read access. We deployed a hacker-container pod with the `superadmin` ServiceAccount:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: popeye-audit
  namespace: kube-system
spec:
  serviceAccountName: superadmin
  containers:
  - name: popeye-audit
    image: madhuakula/hacker-container
    command: ["sleep", "3600"]
  restartPolicy: Never
```

### Step 2: Install Updated Popeye

The hacker-container ships with Popeye 0.9.0 (2020), which has API compatibility issues with modern Kubernetes. We installed a newer version:

```bash
# Download Popeye 0.21.3
curl -sL https://github.com/derailed/popeye/releases/download/v0.21.3/popeye_linux_amd64.tar.gz | tar xz -C /tmp
chmod +x /tmp/popeye

# Verify version
/tmp/popeye version
# Version: 0.21.3 (2024-03-27)
```

### Step 3: Run Cluster-Wide Audit

```bash
/tmp/popeye
```

## Audit Results

### Overall Cluster Score: 80/100 (Grade B)

| Resource Type | Score | Issues Found |
|---------------|-------|--------------|
| Cluster | 100 | K8s version OK |
| ClusterRoles | 100 | 72 roles checked, no issues |
| ClusterRoleBindings | 93 | 4 warnings (missing ServiceAccounts) |
| ConfigMaps | 100 | 4 potentially unused |
| **DaemonSets** | **25** | 1 error, 2 warnings |
| **Deployments** | **9** | 8 errors, 2 warnings |
| **Jobs** | **0** | 2 errors, 1 warning |
| **Pods** | **0** | 25 errors, 12 warnings |
| **Services** | **16** | 10 warnings |
| Secrets | 100 | 4 potentially unused |

### Critical Security Findings

#### 1. Containers Running as Root (POP-302/306)
Nearly every workload flagged:
```
[POP-302] Pod could be running as root user. Check SecurityContext/Image
[POP-306] Container could be running as root user. Check SecurityContext/Image
```

**Affected pods:** system-monitor, build-code, health-check, poor-registry, internal-proxy, cache-store, hunger-check

**Connection to exploits:** This is exactly what enabled container escape in Scenario 4.

#### 2. No Network Policies (POP-1204)
Universal finding across all namespaces:
```
[POP-1204] Pod Ingress is not secured by a network policy
[POP-1204] Pod Egress is not secured by a network policy
```

**Connection to exploits:** This allowed namespace bypass in Scenario 11 - any pod could reach cache-store in secure-middleware namespace.

#### 3. Untagged/Latest Images (POP-100/101)
```
[POP-100] Untagged docker image in use
[POP-101] Image tagged "latest" in use
```

**Affected deployments:** build-code, health-check, system-monitor, poor-registry, internal-proxy, cache-store, hunger-check

**Risk:** Supply chain attacks, unpredictable deployments, no audit trail.

#### 4. Default ServiceAccount Usage (POP-300)
```
[POP-300] Uses "default" ServiceAccount
```

**Risk:** Default SA often has more permissions than needed; dedicated SAs enable principle of least privilege.

#### 5. Missing Resource Limits (POP-106)
```
[POP-106] No resources requests/limits defined
```

**Connection to exploits:** This is what enabled DoS attacks in Scenario 13.

#### 6. No Probes Defined (POP-102)
```
[POP-102] No probes defined
```

**Risk:** Kubernetes can't detect unhealthy containers; failed apps continue receiving traffic.

## Namespace Comparison

Tested individual namespace scores to validate attack surface analysis:

| Namespace | Score | Pod Count | Attack Surface |
|-----------|-------|-----------|----------------|
| default | 80/B | 24 | **Highest** - most vulnerable workloads |
| big-monolith | 80/B | 1 | Low |
| secure-middleware | 80/B | 1 | Low |

**Key Insight:** Popeye scores **security hygiene**, not attack surface size. All namespaces have similar *types* of problems, but `default` provides attackers 24x more targets.

## Connecting Findings to Exploits

| Popeye Finding | Code | Scenario Exploited |
|----------------|------|-------------------|
| Running as root | POP-302 | Scenario 4 (Container Escape) |
| No Network Policies | POP-1204 | Scenario 11 (Namespace Bypass) |
| Untagged images | POP-100 | Scenario 7 (Private Registry) |
| No resource limits | POP-106 | Scenario 13 (DoS Attack) |
| Default ServiceAccount | POP-300 | Scenario 16 (RBAC Misconfiguration) |

This demonstrates Popeye's value: **it would have flagged every vulnerability we exploited** before attackers found them.

## Key Lessons

### 1. Live Cluster Analysis Catches Drift

Static manifest scanning misses:
- Kubectl apply commands not in git
- Helm value overrides
- Operator-created resources
- Manual "emergency" changes

Popeye sees the **truth** of what's running.

### 2. Score vs Attack Surface

A cluster can score well while having massive attack surface:
- 100 pods with identical issues = same score as 1 pod
- But 100 pods = 100x more entry points for attackers

**Combine Popeye with resource inventory for complete picture.**

### 3. Severity Levels Guide Prioritization

| Level | Meaning | Action |
|-------|---------|--------|
| 0 (OK) | Best practice followed | None |
| 1 (Info) | Minor improvement possible | Low priority |
| 2 (Warning) | Should be addressed | Medium priority |
| 3 (Error) | Security/stability risk | **Fix immediately** |

### 4. CI/CD Integration

Fail deployments that degrade cluster score:

```bash
# In CI/CD pipeline
SCORE=$(popeye -o json | jq '.popeye.score')
if [ "$SCORE" -lt 70 ]; then
  echo "Cluster score $SCORE below threshold"
  exit 1
fi
```

## Commands Reference

```bash
# Full cluster scan
popeye

# Scan specific namespace
popeye -n default

# JSON output for parsing
popeye -o json

# Scan specific resource types
popeye -s po,svc,sa,dp

# Save HTML report
popeye -o html > cluster-report.html

# Use custom spinach config (tune checks)
popeye -f spinach.yaml
```

## Spinach Configuration (Custom Rules)

Create `spinach.yaml` to tune Popeye behavior:

```yaml
popeye:
  # Set minimum score threshold
  allocations:
    cpu:
      under: 50%
      over: 90%
    memory:
      under: 50%
      over: 90%

  # Exclude namespaces
  excludes:
    namespaces:
      - kube-system
      - monitoring

  # Adjust severity levels
  overrides:
    - resource: pods
      codes:
        - code: 102  # No probes
          level: info  # Downgrade from warning
```

## MITRE ATT&CK Relevance

Popeye findings map to attack techniques:

| Technique | ID | Popeye Detection |
|-----------|-----|------------------|
| Privilege Escalation | T1611 | POP-302 (root containers) |
| Lateral Movement | T1021 | POP-1204 (no network policies) |
| Resource Hijacking | T1496 | POP-106 (no resource limits) |
| Supply Chain Compromise | T1195 | POP-100/101 (untagged images) |
| Valid Accounts | T1078 | POP-300 (default SA usage) |

## References

- [Popeye Official Documentation](https://popeyecli.io/)
- [Popeye GitHub Repository](https://github.com/derailed/popeye)
- [Popeye Spinach Configuration](https://github.com/derailed/popeye#spinach)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
