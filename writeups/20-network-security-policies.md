# Scenario 20: Secure Network Boundaries using Network Security Policies

## Overview

This scenario demonstrates how to implement **Kubernetes Network Policies** to create micro-segmentation and protect sensitive workloads from lateral movement attacks. By default, Kubernetes operates with a flat network model where every pod can communicate with every other pod - a significant security gap that Network Policies address.

## The Problem: Default Kubernetes Networking

### Flat Network Model

Without Network Policies, Kubernetes clusters have **no network segmentation**:

| From Pod | Can Reach | Result |
|----------|-----------|--------|
| Any pod in `default` | Redis in `secure-middleware` | Allowed |
| Any pod in `default` | Kubernetes API | Allowed |
| Any pod in `big-monolith` | Pods in `default` | Allowed |
| Compromised container | Everything | **Lateral movement enabled** |

### Proof of Concept

Before applying any Network Policies, we tested cross-namespace connectivity:

```bash
# From build-code pod in default namespace
nc -zv 10.244.0.10 6379
# 10.244.0.10 (10.244.0.10:6379) open

# Redis in secure-middleware is reachable from any pod
```

**Security Impact:** An attacker who compromises ANY pod can pivot to:
- Databases and caches in other namespaces
- Internal APIs and microservices
- Kubernetes API server
- External C2 infrastructure (data exfiltration)

## CNI Plugin Requirement

### Critical Discovery

Network Policies are Kubernetes API objects, but **enforcement requires a CNI plugin that supports them**:

| CNI Plugin | Network Policy Support |
|------------|----------------------|
| kindnet (Kind default) | **No** |
| flannel | **No** |
| **Calico** | **Yes** |
| **Cilium** | **Yes** |
| **Weave** | **Yes** |
| AWS VPC CNI (EKS default) | **No** |

### The Silent Failure Mode

This is a critical operational security issue:
1. Kubernetes API **accepts** NetworkPolicy resources regardless of CNI
2. Resources are created successfully (no errors)
3. But if CNI doesn't support them, **policies do nothing**
4. Teams believe they're protected when they're not

### Installing Calico on Kind

```bash
# Install Calico for Network Policy enforcement
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml

# Verify Calico is running
kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=120s
```

## Network Policy Concepts

### Policy Types

| Type | Controls | Pod Perspective |
|------|----------|-----------------|
| **Ingress** | Incoming traffic | "Who can talk to me?" |
| **Egress** | Outgoing traffic | "Who can I talk to?" |

### Key Behaviors

1. **Default (no policies):** All traffic allowed in both directions
2. **Policy applied:** Pod becomes "isolated" for that direction
3. **Isolation = deny by default:** Only explicitly allowed traffic passes
4. **Multiple policies:** Union of all rules (additive, not overriding)

### Policy Anatomy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cache-store-allow-ingress
  namespace: secure-middleware          # Policy lives in target's namespace
spec:
  podSelector:
    matchLabels:
      app: cache-store                   # Apply to pods with this label
  policyTypes:
  - Ingress                              # Control incoming traffic
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: internal-proxy            # Allow pods with this label
      namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default  # From this namespace
    ports:
    - protocol: TCP
      port: 6379                         # On this port only
```

### Selector Logic

When `podSelector` and `namespaceSelector` are in the **same array item**:
- Both conditions must match (AND logic)
- Pod must have label AND be in namespace

When they are **separate array items**:
- Either condition allows traffic (OR logic)

## Implementation Walkthrough

### Step 1: Identify Target Pod Labels

```bash
kubectl get pod -n secure-middleware -l app=cache-store -o jsonpath='{.items[0].metadata.labels}'
# {"app":"cache-store","pod-template-hash":"7c4d798b67"}
```

### Step 2: Design Access Policy

We chose to allow only the `internal-proxy` app to access Redis, applying least privilege:

| Decision | Rationale |
|----------|-----------|
| Allow by app label | Least privilege - only named apps |
| Require namespace match | Prevent cross-namespace spoofing |
| Specific port only | Defense in depth |

### Step 3: Apply Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cache-store-allow-ingress
  namespace: secure-middleware
spec:
  podSelector:
    matchLabels:
      app: cache-store
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: internal-proxy
      namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default
    ports:
    - protocol: TCP
      port: 6379
```

### Step 4: Verify Enforcement

```bash
# From build-code pod (app=build-code) - should be BLOCKED
nc -zv -w 3 10.244.0.10 6379
# nc: 10.244.0.10 (10.244.0.10:6379): Operation timed out

# From internal-proxy pod (app=internal-proxy) - should be ALLOWED
nc -zv -w 3 10.244.0.10 6379
# 10.244.0.10 (10.244.0.10:6379) open
```

## EKS and Cloud Provider Considerations

### AWS EKS

EKS uses the **VPC CNI** by default, which does NOT enforce Network Policies. Options:

1. **Install Calico alongside VPC CNI** (most common)
2. **Use Cilium** (replaces VPC CNI)
3. **AWS VPC CNI Network Policy Controller** (newer, 2023+)

### Defense in Depth: Security Groups + Network Policies

| Layer | Tool | Controls |
|-------|------|----------|
| **VPC/Node** | Security Groups, NACLs | Traffic in/out of nodes, AWS service access |
| **Pod** | Network Policies | Pod-to-pod traffic, micro-segmentation |

Security Groups cannot see pod-level traffic - they only see "traffic from node." Network Policies provide the granular pod-level control.

### GKE and AKE

- **GKE:** Network Policies supported when enabled during cluster creation
- **AKS:** Azure CNI supports Network Policies with Calico or Azure NPM

## Common Network Policy Patterns

### Default Deny All Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: secure-middleware
spec:
  podSelector: {}     # Empty = all pods in namespace
  policyTypes:
  - Ingress           # No ingress rules = deny all
```

### Default Deny All Egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: secure-middleware
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

### Allow DNS (Required for Most Workloads)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: secure-middleware
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

### Namespace Isolation

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: namespace-isolation
  namespace: secure-middleware
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}  # Only pods in same namespace
```

## Key Lessons

### 1. Network Policies Require CNI Support

Always verify your CNI supports Network Policies:
```bash
kubectl get pods -n kube-system | grep -E 'calico|cilium|weave'
```

If you see only `kindnet`, `flannel`, or `aws-node`, you need to install a policy-capable CNI.

### 2. Test Policy Enforcement

Never assume policies work - always test:
```bash
# From a pod that SHOULD be blocked
nc -zv -w 3 <target-ip> <port>
# Expected: timeout or connection refused
```

### 3. Start with Default Deny

The most secure approach:
1. Apply default-deny to namespace
2. Explicitly allow required traffic
3. Monitor for blocked traffic (via CNI logs)

### 4. Labels Are Critical

Network Policies rely entirely on labels for pod selection:
- Use consistent labeling conventions
- Avoid labels that attackers could spoof
- Consider namespace selectors for additional security

## MITRE ATT&CK Mapping

| Technique | ID | Network Policy Defense |
|-----------|-----|----------------------|
| Lateral Movement | T1021 | Block pod-to-pod traffic |
| Remote Services | T1021.007 | Restrict service access by label |
| Network Service Discovery | T1046 | Limit which pods can probe others |
| Exfiltration Over C2 | T1041 | Egress policies block external access |

## OWASP Kubernetes Top 10

- **K02: Supply Chain Vulnerabilities** - Even compromised pods can't reach sensitive services
- **K03: Overly Permissive RBAC** - Network policies provide defense when RBAC is bypassed
- **K04: Lack of Centralized Policy Enforcement** - Network Policies enforce at network layer

## References

- [Kubernetes Network Policies Documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Calico Network Policy Guide](https://docs.tigera.io/calico/latest/network-policy/)
- [Cilium Network Policy Tutorial](https://docs.cilium.io/en/stable/security/policy/)
- [AWS EKS Network Policy Support](https://docs.aws.amazon.com/eks/latest/userguide/calico.html)
- [Network Policy Editor (Visual Tool)](https://editor.networkpolicy.io/)
