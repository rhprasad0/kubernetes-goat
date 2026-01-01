# Scenario 22: Kyverno - Kubernetes Policy Engine

## Overview

This scenario explores **Kyverno**, a policy engine designed specifically for Kubernetes. Unlike traditional policy engines that require learning a new language (like Rego for OPA), Kyverno policies are native Kubernetes resources written in YAML. This makes policy-as-code accessible to teams already familiar with Kubernetes manifests.

## Why Policy Engines Matter

Throughout the previous 21 scenarios, we exploited numerous misconfigurations:
- Privileged containers (Scenario 4)
- Missing resource limits (Scenario 13)
- Containers running as root (Scenario 16)
- Missing network policies (Scenario 11)

**Policy engines prevent these misconfigurations from ever being deployed.** They act as guardrails, enforcing organizational security standards at admission time.

## How Kyverno Works

Kyverno operates as a **dynamic admission controller** in the Kubernetes API request flow:

```
kubectl apply → API Server → Authentication → Authorization (RBAC)
                                                    ↓
                                          Admission Controllers
                                                    ↓
                                              ┌─────────────┐
                                              │   Kyverno   │
                                              │  Validate   │
                                              │   Mutate    │
                                              │  Generate   │
                                              └─────────────┘
                                                    ↓
                                                  etcd
```

When a resource is created/updated, Kyverno intercepts the request and:
1. **Validates** - Accepts or rejects based on policy rules
2. **Mutates** - Modifies resources to comply with policies
3. **Generates** - Creates additional resources (e.g., NetworkPolicies)

## Installation

Deployed Kyverno using Helm:

```bash
# Add Kyverno Helm repository
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

# Install Kyverno
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --wait
```

### Kyverno Components

| Component | Purpose |
|-----------|---------|
| `kyverno-admission-controller` | Validates/mutates incoming requests |
| `kyverno-background-controller` | Scans existing resources |
| `kyverno-cleanup-controller` | Handles cleanup policies |
| `kyverno-reports-controller` | Generates policy reports |

## The Challenge: Blocking Exec in Sensitive Namespaces

### Scenario Setup

Created a `vault` namespace to simulate a sensitive environment containing secrets:

```bash
kubectl create namespace vault
kubectl --namespace vault run kubernetes-goat-secrets \
  --image=madhuakula/k8s-goat-info-app --port=5000 --restart=Never
```

### The Problem

By default, anyone with `pods/exec` permissions can shell into any pod:

```bash
kubectl --namespace vault exec -it kubernetes-goat-secrets -- sh
# Works! Full shell access to "secure" pod
```

This is dangerous for namespaces containing:
- Secret managers (HashiCorp Vault)
- Databases with sensitive data
- Payment processing systems

### The Solution: Kyverno ClusterPolicy

Created a policy to block `exec` into any pod in the `vault` namespace:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-exec-in-vault-namespace
  annotations:
    policies.kyverno.io/title: Block Pod Exec in Vault Namespace
    policies.kyverno.io/category: Security
    policies.kyverno.io/description: >-
      Blocks kubectl exec into any pod in the vault namespace to protect
      sensitive secrets from interactive access.
spec:
  validationFailureAction: Enforce    # Block (not just audit)
  background: false                   # Only check live requests
  rules:
  - name: deny-exec-ns-vault
    match:
      any:
      - resources:
          kinds:
          - Pod/exec                  # Subresource syntax is critical!
    preconditions:
      all:
      - key: "{{ request.operation || 'BACKGROUND' }}"
        operator: Equals
        value: CONNECT                # Exec uses CONNECT operation
    validate:
      message: "Exec into pods in the vault namespace is blocked by policy."
      deny:
        conditions:
          any:
          - key: "{{ request.namespace }}"
            operator: Equals
            value: vault
```

### Key Implementation Detail

The resource kind must be `Pod/exec` (subresource syntax), NOT `PodExecOptions`:

| Syntax | Result |
|--------|--------|
| `kinds: ["PodExecOptions"]` | Policy created but NOT enforced |
| `kinds: ["Pod/exec"]` | Policy actively blocks exec |

This is because `exec` is a subresource of Pod, not a standalone resource type.

### Verification

```bash
# Attempt to exec into vault namespace - BLOCKED
kubectl --namespace vault exec -it kubernetes-goat-secrets -- sh
# Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
# resource PodExecOptions/vault/ was blocked due to the following policies
# deny-exec-in-vault-namespace:
#   deny-exec-ns-vault: "Exec into pods in the vault namespace is blocked by policy."

# Exec into other namespaces - ALLOWED
kubectl exec -it <pod-in-default> -- sh
# Works normally
```

## Policy Enforcement Modes

Kyverno supports two enforcement modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `Enforce` | Blocks non-compliant resources | Production enforcement |
| `Audit` | Allows but logs violations | Policy testing, gradual rollout |

```yaml
spec:
  validationFailureAction: Enforce  # or Audit
```

## Common Kyverno Use Cases

### 1. Require Resource Limits (Prevent DoS - Scenario 13)

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
      any:
      - resources:
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

### 2. Block Privileged Containers (Prevent Escape - Scenario 4)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-privileged
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - securityContext:
              privileged: "!true"
```

### 3. Auto-Generate NetworkPolicies (Prevent Bypass - Scenario 11)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-networkpolicy
spec:
  rules:
  - name: default-deny-ingress
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      kind: NetworkPolicy
      apiVersion: networking.k8s.io/v1
      name: default-deny-ingress
      namespace: "{{request.object.metadata.name}}"
      data:
        spec:
          podSelector: {}
          policyTypes:
          - Ingress
```

## Kyverno vs OPA Gatekeeper

| Feature | Kyverno | OPA Gatekeeper |
|---------|---------|----------------|
| Policy Language | YAML (Kubernetes native) | Rego (custom DSL) |
| Learning Curve | Low | High |
| Mutation Support | Yes | Limited |
| Generate Resources | Yes | No |
| CLI Testing | `kyverno test` | `opa test` |
| Community Policies | [kyverno.io/policies](https://kyverno.io/policies/) | [gatekeeper-library](https://github.com/open-policy-agent/gatekeeper-library) |

**Choose Kyverno** if your team is already proficient with Kubernetes YAML.
**Choose OPA** if you need complex logic or use OPA elsewhere (Terraform, CI/CD).

## Connecting to Previous Scenarios

| Scenario | Vulnerability | Kyverno Prevention |
|----------|--------------|-------------------|
| 4 - Container Escape | Privileged containers | Disallow privileged: true |
| 11 - Namespace Bypass | No network isolation | Auto-generate NetworkPolicies |
| 13 - DoS Resources | No resource limits | Require limits on all pods |
| 15 - Hidden in Layers | Unverified images | Require image signatures |
| 16 - RBAC Misconfig | Overly permissive roles | Block wildcard RBAC rules |

## MITRE ATT&CK Mapping

| Technique ID | Name | Kyverno Mitigation |
|--------------|------|-------------------|
| T1609 | Container Administration Command | Block exec in sensitive namespaces |
| T1610 | Deploy Container | Require image signature verification |
| T1611 | Escape to Host | Disallow privileged containers |
| T1613 | Container Discovery | Restrict API access via RBAC policies |

## Real-World Applications

### CI/CD Integration

```bash
# Test policies against manifests before deployment
kyverno apply policy.yaml --resource deployment.yaml

# Fail pipeline if violations found
kyverno apply policy.yaml --resource deployment.yaml || exit 1
```

### GitOps Workflow

```
Developer PR → Kyverno CLI (test) → Merge → ArgoCD → Kyverno (enforce)
                    ↓
              Block invalid
              manifests early
```

### Compliance Reporting

```bash
# View policy reports across cluster
kubectl get policyreports -A
kubectl get clusterpolicyreports
```

## Cleanup

```bash
kubectl delete clusterpolicy deny-exec-in-vault-namespace
kubectl delete ns vault kyverno
```

## Key Takeaways

1. **Shift-left security** - Enforce policies at admission time, not after deployment
2. **Kubernetes-native** - No new language required; policies are YAML resources
3. **Defense in depth** - Combine with Falco (runtime), Tetragon (eBPF), and Network Policies
4. **Subresource syntax matters** - Use `Pod/exec` not `PodExecOptions` for exec blocking
5. **Audit before enforce** - Use `Audit` mode to test policies before blocking production traffic

## Tools Used

- **Kyverno 1.16.1** - Kubernetes-native policy engine
- **Helm** - Kubernetes package manager
- **kubectl** - Kubernetes CLI
- **Kubernetes Goat** - Intentionally vulnerable cluster

## References

- [Kyverno Documentation](https://kyverno.io/docs/)
- [Kyverno Policy Library](https://kyverno.io/policies/)
- [Kyverno GitHub](https://github.com/kyverno/kyverno)
- [Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

---

*Completed with guidance from Claude Code (Anthropic) - AI-assisted security analysis and documentation*
