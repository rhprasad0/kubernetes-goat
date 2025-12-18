# Scenario 8: NodePort Exposed Services

## Overview

This challenge demonstrates the risks of exposing Kubernetes services via NodePort without proper network controls. From an external attacker's perspective (no kubectl credentials), we performed network reconnaissance to discover and access internal services that should not be publicly reachable.

## Attack Vector

Kubernetes NodePort services expose applications on a static port (30000-32767) across all cluster nodes. Without network policies or firewall rules, anyone with network access to the nodes can reach these services, bypassing the intended access controls.

## Tools Used

- **nmap** - Network discovery and port scanning
- **curl** - HTTP service interaction
- **Standard networking utilities** - ip, ping

## Attack Walkthrough

### Step 0: Simulating External Attacker Position

Removed kubectl credentials to simulate an external attacker with only network access:

```bash
# Backup and remove kubeconfig
cp ~/.kube/config ~/.kube/config.backup
rm ~/.kube/config

# Verify no cluster access
kubectl get pods
# Error: no configuration found
```

### Step 1: Network Reconnaissance

Identified the target network by examining available interfaces:

```bash
ip addr show | grep -E "inet " | grep -v 127.0.0.1
```

**Result**: Multiple Docker bridge networks discovered (172.17.x, 172.18.x, 172.19.x)

### Step 2: Host Discovery

Used nmap ping sweep to find live hosts on the Docker networks:

```bash
sudo nmap -sn 172.19.0.0/24
```

**Result**:
```
Nmap scan report for 172.19.0.2
Host is up (0.000025s latency).
```

Found the Kind cluster control-plane node at `172.19.0.2`.

### Step 3: NodePort Range Scanning

Scanned the Kubernetes NodePort range to discover exposed services:

```bash
sudo nmap -sT -p 30000-32767 172.19.0.2 --open
```

**Result**:
```
PORT      STATE SERVICE
30003/tcp open  amicon-fpsu-ra
```

**Key Insight**: NodePort range is 30000-32767 by default. Any open port in this range indicates an exposed Kubernetes service.

### Step 4: Service Fingerprinting

Performed service version detection on the discovered port:

```bash
sudo nmap -sV -p 30003 172.19.0.2
```

**Result**:
- Server: Werkzeug/3.0.1 Python/3.12.0
- Response leaked internal architecture: `{"info": "Refer to internal http://metadata-db for more information"}`

### Step 5: Service Interaction

Accessed the exposed service directly:

```bash
curl -s http://172.19.0.2:30003/
```

**Result**:
```json
{"info": "Refer to internal http://metadata-db for more information"}
```

**Finding**: The exposed service reveals the existence of an internal `metadata-db` service, providing valuable reconnaissance information for further attacks.

## Architecture Analysis

Examined the Kubernetes manifests to understand the exposure:

```yaml
# internal-proxy/deployment.yaml
apiVersion: v1
kind: Service
metadata:
  name: internal-proxy-info-app-service
spec:
  type: NodePort          # <-- Exposed externally
  ports:
  - protocol: TCP
    port: 5000
    targetPort: 5000
    nodePort: 30003       # <-- Static port assignment
  selector:
    app: internal-proxy
```

**Issue**: The service is explicitly configured as NodePort with a static port, making it accessible from any network that can reach the cluster nodes.

## Key Lessons

### Why This Matters

1. **NodePort bypasses ingress controls** - Services are directly accessible on node IPs, circumventing any Ingress-level security
2. **Information disclosure** - Even "harmless" info pages can reveal internal architecture to attackers
3. **Default-open posture** - NodePort assumes network-level security exists; without it, services are publicly accessible
4. **Reconnaissance enabler** - Discovered services help attackers map internal infrastructure for further exploitation

### Real-World Impact

- **Misconfigured databases** - MongoDB, Redis, Elasticsearch exposed via NodePort have led to massive data breaches
- **Internal APIs** - Admin endpoints accidentally exposed enable privilege escalation
- **Metadata services** - Cloud metadata endpoints exposed internally can be pivoted to via SSRF

## Mitigations

### Network Security

| Control | Description |
|---------|-------------|
| **Network Policies** | Restrict pod-to-pod and external traffic at the CNI level |
| **Cloud Firewalls** | Block NodePort range (30000-32767) from untrusted networks |
| **Private Clusters** | Use clusters with no public node IPs |
| **VPN/Bastion** | Require VPN access to reach cluster networks |

### Service Configuration

| Avoid | Prefer |
|-------|--------|
| `type: NodePort` | `type: ClusterIP` with Ingress |
| Static nodePort assignment | Let K8s auto-assign if NodePort needed |
| Exposing debug/info endpoints | Remove or protect non-essential endpoints |

### Kubernetes Best Practices

```yaml
# AVOID: NodePort exposure
apiVersion: v1
kind: Service
spec:
  type: NodePort  # Accessible on all nodes

# PREFER: ClusterIP with Ingress
apiVersion: v1
kind: Service
spec:
  type: ClusterIP  # Internal only
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    # Add authentication, rate limiting, etc.
spec:
  rules:
  - host: myapp.example.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: my-service
```

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Network Service Discovery | T1046 | Port scanning to discover NodePort services |
| Remote System Discovery | T1018 | Identified cluster nodes via network scanning |
| System Information Discovery | T1082 | Extracted internal architecture details from exposed service |

## Commands Reference

```bash
# Host discovery on a network
nmap -sn 192.168.1.0/24

# Scan NodePort range
nmap -sT -p 30000-32767 <node-ip> --open

# Service version detection
nmap -sV -p <port> <node-ip>

# Quick TCP connect scan
nc -zv <node-ip> 30000-32767

# Access discovered service
curl http://<node-ip>:<nodeport>/
```

## References

- [Kubernetes Services - NodePort](https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CIS Kubernetes Benchmark - Network Security](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
