# Kubernetes Security Learning Lab

A hands-on journey through Kubernetes security using [Kubernetes Goat](https://madhuakula.com/kubernetes-goat) - an intentionally vulnerable cluster environment for learning container and cloud-native security.

## About This Project

I'm an entry-level DevOps professional building practical security skills through CTF-style challenges. This repository documents my progression from cloud security fundamentals to Kubernetes-specific attack and defense techniques.

### Learning Path Completed

| CTF/Lab | Focus Area | Status |
|---------|------------|--------|
| [flaws.cloud](http://flaws.cloud) | AWS Security Misconfigurations | Completed |
| [flaws2.cloud](http://flaws2.cloud) | AWS Attack & Defense Paths | Completed |
| **Kubernetes Goat** | Container & K8s Security | In Progress |

## Skills Demonstrated

### Offensive Security (Red Team)
- Container escape techniques and privilege escalation
- Kubernetes API enumeration and exploitation
- SSRF attacks against cloud metadata services
- Docker image layer analysis for secret extraction
- RBAC misconfiguration exploitation
- Namespace boundary bypass attacks

### Defensive Security (Blue Team)
- CIS Benchmark compliance scanning (Docker & Kubernetes)
- Runtime threat detection with Falco
- Network segmentation using Network Security Policies
- eBPF-based observability with Cilium Tetragon
- Policy enforcement with Kyverno and OPA

### DevSecOps Practices
- Security scanning in CI/CD pipelines
- Infrastructure-as-Code security analysis
- Container image vulnerability assessment
- Kubernetes cluster hardening

## Challenge Progress

### Attack Scenarios
| # | Scenario | Skills | Status |
|---|----------|--------|--------|
| 1 | Sensitive Keys in Codebases | Secret detection, code review | |
| 2 | DIND Exploitation | Docker socket abuse, container breakout | |
| 3 | SSRF in Kubernetes | Cloud metadata, service discovery | |
| 4 | Container Escape to Host | Privileged containers, hostPID | |
| 7 | Attacking Private Registry | Registry enumeration, image pulling | |
| 8 | NodePort Exposed Services | Service discovery, network exposure | |
| 10 | Crypto Miner Analysis | Malware analysis, forensics | |
| 11 | Namespace Bypass | Cross-namespace attacks, network policies | |
| 12 | Environment Information | Enumeration, information disclosure | |
| 13 | DoS Resources | Resource limits, quotas | |
| 15 | Hidden in Layers | Docker history, layer extraction | |
| 16 | RBAC Misconfiguration | Permission escalation, role binding | |

### Defense & Tooling Scenarios
| # | Scenario | Tool/Technique | Status |
|---|----------|----------------|--------|
| 5 | Docker CIS Benchmarks | docker-bench-security | |
| 6 | Kubernetes CIS Benchmarks | kube-bench | |
| 14 | Hacker Container | Offensive security toolkit | |
| 17 | KubeAudit | Cluster auditing | |
| 18 | Falco | Runtime security monitoring | |
| 19 | Popeye | Cluster sanitization | |
| 20 | Network Security Policies | Network segmentation | |
| 21 | Cilium Tetragon | eBPF security observability | |
| 22 | Kyverno Policy Engine | Policy-as-code | |

## Environment Setup

This lab runs in a development container connected to a Kind (Kubernetes in Docker) cluster:

```bash
# Cluster is pre-configured with vulnerable scenarios
kubectl get pods -A

# Access the lab interface
bash access-kubernetes-goat.sh
# Navigate to http://127.0.0.1:1234
```

## Key Learnings

*This section will be updated as I complete each scenario with specific takeaways and real-world implications.*

### Example Entry Format:
> **Scenario X: [Name]**
> - **Attack Vector**: Brief description of the vulnerability
> - **Real-World Risk**: How this applies to production environments
> - **Mitigation**: Defensive measures to prevent this attack
> - **Tools Used**: Security tools employed in detection/exploitation

## Relevant Frameworks

This learning aligns with industry security frameworks:

- **OWASP Kubernetes Top 10** - Common K8s security risks
- **MITRE ATT&CK for Containers** - Adversary tactics and techniques
- **CIS Benchmarks** - Security configuration standards
- **NIST Container Security Guide** - Federal security guidelines

## Resources

- [Kubernetes Goat Official Docs](https://madhuakula.com/kubernetes-goat)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)

## Connect

Building DevOps skills with a security-first mindset. Open to opportunities in DevOps, Platform Engineering, and Cloud Security roles.

---

*This is a learning environment with intentionally vulnerable configurations. Never deploy these patterns in production.*
