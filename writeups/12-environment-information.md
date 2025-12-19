# Scenario 12: Gaining Environment Information

## Overview

This challenge demonstrates how attackers enumerate a Kubernetes environment after gaining initial access to a container. When an attacker exploits a vulnerability like RCE (Remote Code Execution) or command injection, their first objective is reconnaissance - understanding where they are and what they can access.

Kubernetes automatically injects significant amounts of information into every pod, creating a rich attack surface for information disclosure.

## Attack Vector

When an attacker lands inside a Kubernetes pod, they have immediate access to:

| Information Type | Location | Risk Level |
|------------------|----------|------------|
| Environment variables | `printenv`, `/proc/*/environ` | Critical - often contains secrets |
| Service account token | `/var/run/secrets/kubernetes.io/serviceaccount/token` | High - enables API access |
| Cluster CA certificate | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | Medium - validates API server |
| Namespace | `/var/run/secrets/kubernetes.io/serviceaccount/namespace` | Low - orientation info |
| Service discovery | Environment variables for all services | Medium - reveals internal topology |
| Container runtime info | `/proc/self/cgroup` | Low - identifies container runtime |

## Tools Used

- **printenv / env** - List environment variables
- **cat** - Read files
- **mount** - View mounted filesystems
- **curl** - Query Kubernetes API

## Attack Walkthrough

### Step 1: Access the Container

For this scenario, we used the `system-monitor` pod which exposes a web terminal:

```bash
# Port forward is already set up via access-kubernetes-goat.sh
# Access http://127.0.0.1:1233 for web terminal
# Or exec directly:
kubectl exec -it system-monitor-deployment-<pod-id> -- /bin/sh
```

### Step 2: Enumerate Environment Variables

The first reconnaissance command every attacker runs:

```bash
printenv
```

**Result** (key findings):
```
K8S_GOAT_VAULT_KEY=k8s-goat-cd2da27224591da2b48ef83826a8a6c3
KUBERNETES_SERVICE_HOST=10.96.0.1
KUBERNETES_SERVICE_PORT=443
BUILD_CODE_SERVICE_PORT=tcp://10.96.225.73:3000
HEALTH_CHECK_SERVICE_SERVICE_HOST=10.96.120.169
INTERNAL_PROXY_API_SERVICE_SERVICE_HOST=10.96.53.228
POOR_REGISTRY_SERVICE_SERVICE_HOST=10.96.86.249
METADATA_DB_SERVICE_HOST=10.96.230.40
...
```

**Critical Finding**: `K8S_GOAT_VAULT_KEY` - A secret value exposed as an environment variable!

**Bonus Finding**: Every service in the namespace has its IP and port exposed via environment variables, revealing the entire internal network topology.

### Step 3: Examine Service Account Token

Kubernetes automatically mounts credentials for API access:

```bash
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
```

**Result**:
```
ca.crt    -> Cluster CA certificate
namespace -> "default"
token     -> JWT authentication token
```

### Step 4: Decode the JWT Token

The service account token is a JWT containing valuable information:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d'.' -f2 | base64 -d
```

**Result**:
```json
{
  "kubernetes.io": {
    "namespace": "default",
    "pod": {
      "name": "system-monitor-deployment-54fd6f868b-mfpml"
    },
    "serviceaccount": {
      "name": "default"
    },
    "node": {
      "name": "kubernetes-goat-cluster-control-plane"
    }
  }
}
```

**Finding**: The token reveals pod name, namespace, service account, and node information.

### Step 5: Test API Access

Using the token to query the Kubernetes API:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

**Result**:
```json
{
  "status": "Failure",
  "message": "secrets is forbidden: User \"system:serviceaccount:default:default\" cannot list resource \"secrets\"",
  "code": 403
}
```

**Finding**: This particular service account is properly locked down (good security!). However, misconfigured RBAC would allow secrets access.

### Step 6: Check Actual Permissions

Query what the service account CAN do:

```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
```

**Result**: Only basic permissions - self-subject access reviews and non-resource URLs.

## Key Lessons

### The Environment Variable Anti-Pattern

| Common Mistake | Risk | Better Approach |
|----------------|------|-----------------|
| Secrets as env vars | Visible via `printenv`, `/proc/*/environ` | Mount as files with restrictive perms |
| Database passwords in env | Any RCE exposes credentials | Use external secret managers (Vault) |
| API keys in pod spec | Stored in etcd, visible in pod describe | Use Kubernetes Secrets (still not ideal) |
| Static credentials | Long-lived, hard to rotate | Use workload identity, short-lived tokens |

### What Kubernetes Injects Automatically

Every pod receives:

```yaml
# Automatically mounted (unless disabled)
/var/run/secrets/kubernetes.io/serviceaccount/
├── token      # JWT for API auth
├── ca.crt     # Cluster CA
└── namespace  # Pod's namespace

# Automatically set as environment variables
KUBERNETES_SERVICE_HOST=10.96.0.1
KUBERNETES_SERVICE_PORT=443
<SERVICE_NAME>_SERVICE_HOST=<ip>
<SERVICE_NAME>_SERVICE_PORT=<port>
```

### Service Discovery via Environment Variables

The `*_SERVICE_HOST` and `*_SERVICE_PORT` variables reveal:
- All services in the namespace
- Their ClusterIP addresses
- Their ports

This enables network reconnaissance without any API access.

## Defense Recommendations

### Immediate Actions

1. **Audit environment variables** - Remove secrets from pod specs
2. **Disable token automount** where not needed:
   ```yaml
   spec:
     automountServiceAccountToken: false
   ```

### Secure Secret Management

| Approach | Security Level | Notes |
|----------|---------------|-------|
| Env vars from Secrets | Low | Still visible via printenv |
| Volume-mounted Secrets | Medium | File permissions apply |
| External Secrets Operator | High | Syncs from Vault, AWS SM, etc. |
| CSI Secret Store Driver | High | Mounts secrets from external stores |
| Workload Identity | Highest | No static secrets in cluster |

### Example: Mount Secrets as Files

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  automountServiceAccountToken: false  # Disable if not needed
  containers:
    - name: app
      image: myapp:latest
      volumeMounts:
        - name: secrets
          mountPath: /etc/secrets
          readOnly: true
  volumes:
    - name: secrets
      secret:
        secretName: app-secrets
        defaultMode: 0400  # Read-only for owner
```

### Example: Use External Secrets

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: app-secrets
  data:
    - secretKey: api-key
      remoteRef:
        key: secret/data/myapp
        property: api-key
```

## Real-World Impact

### Why This Matters

| Statistic | Source |
|-----------|--------|
| 50% of container breaches involve exposed credentials | Sysdig 2023 |
| Environment variables are #1 secret exposure vector | GitGuardian 2023 |
| Average time to exploit exposed credentials: < 1 hour | Unit 42 Research |

### Real Incidents

- **Uber (2016)** - AWS credentials in GitHub led to 57M user data breach
- **Docker Hub (2019)** - Environment variable leak exposed 190K accounts
- **Codecov (2021)** - CI environment variables exfiltrated from thousands of repos

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Container and Resource Discovery | T1613 | Enumerating container environment |
| Unsecured Credentials | T1552.001 | Secrets in environment variables |
| System Information Discovery | T1082 | Gathering host/pod information |
| Account Discovery | T1087 | Identifying service accounts |

## Commands Reference

```bash
# Environment enumeration
printenv
env
cat /proc/self/environ | tr '\0' '\n'

# Service account info
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Decode JWT token
cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Container/pod info
cat /proc/self/cgroup
cat /etc/hosts
hostname
mount

# Test API access
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# List pods (if permitted)
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/pods

# List secrets (if permitted)
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets

# Check own permissions
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
```

## References

- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Injecting Secrets via Vault Agent](https://learn.hashicorp.com/tutorials/vault/kubernetes-sidecar)
- [External Secrets Operator](https://external-secrets.io/)
- [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
- [OWASP Kubernetes Top 10 - K02: Secrets Management](https://owasp.org/www-project-kubernetes-top-ten/)
- [CIS Kubernetes Benchmark - 5.4 Secrets Management](https://www.cisecurity.org/benchmark/kubernetes)
