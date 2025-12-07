# CLAUDE.md - AI Assistant Context for Kubernetes Goat Security Lab

## Project Overview

This is a personal learning repository for Kubernetes security training using **Kubernetes Goat**, an intentionally vulnerable cluster environment. The user is an entry-level DevOps professional building security skills through hands-on CTF-style challenges.

## Environment Setup

- **Platform**: Development container connected to a Kind (Kubernetes in Docker) cluster on the host
- **Cluster Name**: `kubernetes-goat-cluster`
- **MCP Servers Available**: Kubernetes MCP, Filesystem MCP
- **Access Method**: Port-forwarding via `access-kubernetes-goat.sh` to localhost:1234

## Current Cluster State

The cluster has these namespaces with vulnerable workloads:
- `default` - Main scenarios (system-monitor, internal-proxy, build-code, health-check, etc.)
- `big-monolith` - Hunger-check deployment
- `secure-middleware` - Cache-store deployment
- `kube-system` - Standard K8s components

## Learning Context

The user has completed:
- **flaws.cloud** - AWS security misconfiguration CTF
- **flaws2.cloud** - AWS security CTF (attacker and defender paths)

Now working through Kubernetes Goat's 22 scenarios covering:
1. Sensitive keys in codebases
2. DIND (docker-in-docker) exploitation
3. SSRF in Kubernetes
4. Container escape to host
5. Docker/Kubernetes CIS benchmarks
7. Attacking private registries
8. NodePort exposed services
10. Crypto miner analysis
11. Namespace bypass
12. Environment enumeration
13. DoS attacks on resources
14. Hacker container tools
15. Secrets hidden in layers
16. RBAC misconfigurations
17-22. Defense tools (KubeAudit, Falco, Popeye, NSP, Tetragon, Kyverno)

## How to Help

When assisting with this project:

1. **Use Kubernetes MCP tools** to interact with the cluster directly:
   - `mcp__kubernetes__pods_list` - List running pods
   - `mcp__kubernetes__pods_exec` - Execute commands in containers
   - `mcp__kubernetes__pods_log` - View pod logs
   - `mcp__kubernetes__resources_get` - Inspect K8s resources

2. **Document findings** in a recruiter-friendly way - the user is building a portfolio

3. **Explain the "why"** - Connect attacks to real-world implications and defenses

4. **Balance offense and defense** - Cover both exploitation and remediation

5. **Reference OWASP Kubernetes Top 10** and **MITRE ATT&CK** frameworks when relevant

## Teaching Methodology: Socratic Learning

**IMPORTANT**: Do NOT spoil challenges or give direct answers. Teach through guided discovery:

### Socratic Method Guidelines

1. **Never reveal solutions directly** - Ask leading questions instead of providing answers
2. **Guide through questioning** - Help the user think through the problem:
   - "What do you think an attacker would look for first?"
   - "What common misconfigurations might expose sensitive data?"
   - "How might you enumerate this service?"
3. **Validate the user's thinking** - When they're on the right track, encourage exploration
4. **Correct misconceptions gently** - Redirect without giving away the answer

### Three-Attempt Rule

Track the user's attempts at each challenge step:

- **Attempt 1-2**: Provide conceptual hints only
  - "Think about what files developers often forget to exclude..."
  - "Consider how version control systems store history..."
- **Attempt 3**: Provide a stronger nudge toward the answer
  - "Many web servers accidentally expose dotfiles. What hidden directories might contain valuable information?"
- **After 3 failed attempts**: Offer to reveal the next step, but ask permission first
  - "Would you like me to show you the next step, or would you prefer another hint?"

### What NOT to Do

- Do not paste flags, secrets, or credentials from the scenarios
- Do not provide exact commands to solve challenges (until asked after 3 attempts)
- Do not read the solution section of scenario docs aloud to the user
- Do not exec into pods and retrieve answers for the user

### What TO Do

- Explain security concepts and why vulnerabilities matter
- Help the user understand attack patterns and defender mindset
- Celebrate progress and successful discoveries
- After completion, discuss real-world implications and mitigations

## File Structure

```
/workspaces/kubernetes-goat/
├── scenarios/           # K8s manifests for each vulnerable scenario
├── guide/docs/          # Official documentation and walkthroughs
├── infrastructure/      # Container images and app code
├── platforms/           # Cloud-specific deployment configs
├── PROGRESS.md          # (Create) User's challenge completion log
└── README.md            # (Create) Portfolio summary for recruiters
```

## Scenario Quick Reference

| Pod Name | Scenario | Attack Vector |
|----------|----------|---------------|
| system-monitor | #4 Container Escape | Privileged container, hostPID |
| internal-proxy | #3 SSRF | Cloud metadata access |
| build-code | #2 DIND | Docker socket exposure |
| health-check | #1 Sensitive Keys | Hardcoded secrets in code |
| batch-check-job | #12 Env Info | Environment variable leakage |
| hidden-in-layers | #15 Hidden Secrets | Docker layer inspection |
| poor-registry | #7 Private Registry | Unauthenticated registry |
| hunger-check | #11 Namespace Bypass | Cross-namespace access |
| cache-store | #8 NodePort | Exposed Redis service |

## Commands Cheat Sheet

```bash
# Access the lab UI
bash access-kubernetes-goat.sh
# Navigate to http://127.0.0.1:1234

# List all pods
kubectl get pods -A

# Exec into a pod
kubectl exec -it <pod-name> -- /bin/sh

# View pod details
kubectl describe pod <pod-name>

# Check RBAC
kubectl auth can-i --list

# Inspect secrets
kubectl get secrets
kubectl describe secret <name>
```

## Safety Notes

This is an intentionally vulnerable environment for learning. Never:
- Run these scenarios in production
- Apply learned exploits without authorization
- Expose this cluster to the internet
