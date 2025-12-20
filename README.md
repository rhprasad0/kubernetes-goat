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
- Container image forensics and crypto miner detection
- RBAC misconfiguration exploitation
- Namespace boundary bypass attacks
- Network reconnaissance and service discovery (nmap)

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

**Legend:** [x] Completed | [~] Partially complete / environment limitation | [ ] Not started

### Attack Scenarios
| # | Scenario | Skills | Completed |
|---|----------|--------|:---------:|
| 1 | Sensitive Keys in Codebases | Secret detection, code review | [x] |
| 2 | DIND Exploitation | Docker socket abuse, container breakout | [x] |
| 3 | SSRF in Kubernetes | Cloud metadata, service discovery | [~] |
| 4 | Container Escape to Host | Privileged containers, hostPID | [x] |
| 7 | Attacking Private Registry | Registry enumeration, image pulling | [x] |
| 8 | NodePort Exposed Services | Service discovery, network exposure | [x] |
| 10 | Crypto Miner Analysis | Malware analysis, forensics | [x] |
| 11 | Namespace Bypass | Cross-namespace attacks, network policies | [x] |
| 12 | Environment Information | Enumeration, information disclosure | [x] |
| 13 | DoS Resources | Resource limits, quotas | [x] |
| 15 | Hidden in Layers | Docker history, layer extraction | [x] |
| 16 | RBAC Misconfiguration | Permission escalation, role binding | [x] |

### Defense & Tooling Scenarios
| # | Scenario | Tool/Technique | Completed |
|---|----------|----------------|:---------:|
| 5 | Docker CIS Benchmarks | docker-bench-security | [~] |
| 6 | Kubernetes CIS Benchmarks | kube-bench | [x] |
| 14 | Hacker Container | Offensive security toolkit | [x] |
| 17 | KubeAudit | Cluster auditing | [x] |
| 18 | Falco | Runtime security monitoring | [ ] |
| 19 | Popeye | Cluster sanitization | [ ] |
| 20 | Network Security Policies | Network segmentation | [ ] |
| 21 | Cilium Tetragon | eBPF security observability | [ ] |
| 22 | Kyverno Policy Engine | Policy-as-code | [ ] |

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

### Scenario 1: Sensitive Keys in Codebases
> - **Attack Vector**: Exposed `.git` directory allows reconstruction of repository history, revealing secrets committed in earlier versions
> - **Real-World Risk**: AWS credentials, API keys, and database passwords exposed this way have led to major breaches (Uber 2016, numerous startups)
> - **Mitigation**: Block `.git` at web server, use pre-commit hooks for secret detection, rotate credentials immediately if exposed
> - **Tools Used**: curl, git internals analysis, zlib decompression
> - **Writeup**: [writeups/01-sensitive-keys-in-codebases.md](writeups/01-sensitive-keys-in-codebases.md)

### Scenario 2: DIND (Docker-in-Docker) Exploitation
> - **Attack Vector**: Command injection in web app + exposed containerd socket enables full container escape
> - **Real-World Risk**: CI/CD pipelines often mount container runtime sockets for image builds; compromise leads to cluster-wide access
> - **Mitigation**: Use rootless build tools (Kaniko, Buildah), never mount runtime sockets, validate all user input, enforce Pod Security Standards
> - **Tools Used**: curl, crictl, command injection techniques
> - **MITRE ATT&CK**: T1059.004 (Unix Shell), T1611 (Escape to Host)
> - **Writeup**: [writeups/02-dind-exploitation.md](writeups/02-dind-exploitation.md)

### Scenario 7: Attacking Private Registry
> - **Attack Vector**: Unauthenticated Docker Registry API exposed internal container images; secrets leaked via ENV directives in Dockerfile history
> - **Real-World Risk**: Private registries often contain proprietary code, embedded credentials, and internal architecture details; anonymous access enables full reconnaissance
> - **Mitigation**: Enable registry authentication, use runtime secrets instead of ENV in Dockerfiles, implement network segmentation, use multi-stage builds to prevent secret leakage
> - **Tools Used**: curl, crane (Google container registry CLI), jq
> - **MITRE ATT&CK**: T1613 (Container Discovery), T1552.001 (Unsecured Credentials)
> - **Writeup**: [writeups/07-attacking-private-registry.md](writeups/07-attacking-private-registry.md)

### Scenario 8: NodePort Exposed Services
> - **Attack Vector**: External network reconnaissance (nmap) discovered Kubernetes NodePort service exposing internal application; no credentials required
> - **Real-World Risk**: NodePort services are accessible on all cluster nodes; without network policies or firewalls, internal services become publicly reachable, enabling reconnaissance and direct attacks
> - **Mitigation**: Use ClusterIP + Ingress instead of NodePort, implement Network Policies, configure cloud firewalls to block NodePort range (30000-32767), use private clusters
> - **Tools Used**: nmap (host discovery, port scanning, service fingerprinting), curl
> - **MITRE ATT&CK**: T1046 (Network Service Discovery), T1018 (Remote System Discovery)
> - **Writeup**: [writeups/08-nodeport-exposed-services.md](writeups/08-nodeport-exposed-services.md)

### Scenario 10: Analyzing Crypto Miner Container
> - **Attack Vector**: Malicious container image from public registry; crypto miner hidden in Dockerfile build layers and git history embedded in image
> - **Real-World Risk**: Attackers upload innocent-looking images to Docker Hub with hidden miners; organizations unknowingly run these, paying for compute while attackers profit from mining
> - **Mitigation**: Inspect image history before pulling (`docker history --no-trunc` or `crane config`), use image allowlisting policies, implement runtime detection (Falco), monitor for unexpected CPU usage
> - **Tools Used**: crane (container registry CLI), git forensics, strings, kubectl
> - **MITRE ATT&CK**: T1496 (Resource Hijacking), T1195.002 (Supply Chain Compromise), T1552.001 (Unsecured Credentials)
> - **Writeup**: [writeups/10-analyzing-crypto-miner.md](writeups/10-analyzing-crypto-miner.md)

### Scenario 11: Kubernetes Namespace Bypass
> - **Attack Vector**: Kubernetes namespaces provide logical separation but no network isolation by default; any pod can communicate with services in any namespace via predictable DNS names
> - **Real-World Risk**: Organizations often deploy databases, caches, and internal APIs in "secure" namespaces assuming isolation; attackers who compromise any pod can pivot across the entire cluster
> - **Mitigation**: Implement Network Policies with default-deny ingress, use CNIs that support network policies (Calico, Cilium), deploy service mesh for mTLS and authorization
> - **Tools Used**: kubectl, redis-cli, nslookup, network reconnaissance
> - **MITRE ATT&CK**: T1021 (Remote Services), T1046 (Network Service Discovery), T1213 (Data from Information Repositories)
> - **Writeup**: [writeups/11-namespace-bypass.md](writeups/11-namespace-bypass.md)

### Scenario 12: Gaining Environment Information
> - **Attack Vector**: Kubernetes automatically injects environment variables, service account tokens, and service discovery information into every pod; secrets stored as environment variables are trivially accessible via `printenv`
> - **Real-World Risk**: 50% of container breaches involve exposed credentials; environment variables are the #1 secret exposure vector; attackers can enumerate the entire cluster topology from a single compromised pod
> - **Mitigation**: Never store secrets in environment variables, mount secrets as files with restrictive permissions, use external secret managers (Vault, AWS Secrets Manager), disable service account token automount when not needed
> - **Tools Used**: printenv, cat, curl, JWT decoding
> - **MITRE ATT&CK**: T1613 (Container Discovery), T1552.001 (Unsecured Credentials), T1082 (System Information Discovery)
> - **Writeup**: [writeups/12-environment-information.md](writeups/12-environment-information.md)

### Scenario 13: DoS the Memory/CPU Resources
> - **Attack Vector**: Kubernetes containers without resource limits can consume unlimited node resources; cgroups show `max` indicating no restrictions; stress-ng tool enables targeted resource exhaustion attacks
> - **Real-World Risk**: 65% of Kubernetes deployments lack resource limits; a single compromised or misbehaving pod can starve critical workloads, trigger OOM killer, and cause cascading node failures across the cluster
> - **Mitigation**: Always set resource requests and limits, implement LimitRanges for namespace defaults, enforce ResourceQuotas for namespace caps, use Kyverno/OPA policies to require limits on all pods
> - **Tools Used**: stress-ng, cgroups filesystem inspection, kubectl
> - **MITRE ATT&CK**: T1496 (Resource Hijacking), T1499 (Endpoint Denial of Service), T1499.002 (Service Exhaustion Flood)
> - **Writeup**: [writeups/13-dos-resources.md](writeups/13-dos-resources.md)

### Scenario 15: Hidden in Layers
> - **Attack Vector**: Docker image layers are immutable; files "deleted" with `rm` in later layers remain fully recoverable from earlier layers; secrets embedded during build persist in image history
> - **Real-World Risk**: Developers commonly add API keys, credentials, or config files during image builds, then delete them thinking they're gone; anyone with pull access can extract all layers and recover these "deleted" secrets
> - **Mitigation**: Use multi-stage builds to isolate build-time secrets, use `docker build --secret` for build-time credentials, scan images with tools like `dive` before publishing, never commit secrets to image layers
> - **Tools Used**: crane (config, manifest, blob), tar, jq
> - **MITRE ATT&CK**: T1552.001 (Unsecured Credentials in Files), T1588.001 (Obtain Capabilities: Malware)
> - **Writeup**: [writeups/15-hidden-in-layers.md](writeups/15-hidden-in-layers.md)

### Scenario 16: RBAC Misconfiguration
> - **Attack Vector**: Overly permissive RBAC Role using wildcard resources (`*`) instead of specific resource types; ServiceAccount token mounted in pod allows API queries; `SelfSubjectRulesReview` API reveals excessive permissions enabling secret extraction
> - **Real-World Risk**: RBAC misconfigurations are among the most common Kubernetes security issues; developers often use wildcards for convenience, inadvertently granting access to secrets, pods, and other sensitive resources; any compromised pod becomes a pivot point for cluster-wide reconnaissance
> - **Mitigation**: Apply principle of least privilege - scope roles to specific resources and verbs; use `automountServiceAccountToken: false` when API access not needed; create dedicated ServiceAccounts per workload; regularly audit RBAC with `kubectl auth can-i --list`; enforce policies with Kyverno/OPA to block wildcard permissions
> - **Tools Used**: curl (Kubernetes API), Kubernetes MCP, base64 decoding
> - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts), T1552 (Unsecured Credentials), T1087 (Account Discovery)
> - **OWASP K8s Top 10**: K01 (Insecure Workload Configurations), K08 (Secrets Management)
> - **Writeup**: [writeups/16-rbac-misconfiguration.md](writeups/16-rbac-misconfiguration.md)

### Scenario 17: KubeAudit - Audit Kubernetes Clusters
> - **Tool Purpose**: Proactive security auditing to detect misconfigurations before attackers exploit them; shifts from offensive exploitation to defensive hardening
> - **Key Findings**: 194+ issues including 4 privileged containers, 3 hostPID violations, 5 sensitive path mounts, 7 namespaces without network policies, 19 containers running as root
> - **Real-World Value**: Security auditing is essential for compliance (SOC2, PCI-DSS, HIPAA) and risk management; kubeaudit can be integrated into CI/CD pipelines to prevent vulnerable deployments
> - **Audit Correlation**: Findings directly mapped to previous exploits - PrivilegedTrue (Scenario 4), SensitivePathsMounted (Scenario 2), MissingNetworkPolicy (Scenario 11), AutomountServiceAccountToken (Scenario 16)
> - **Tools Used**: kubeaudit, madhuakula/hacker-container, Kubernetes MCP
> - **Writeup**: [writeups/17-kubeaudit.md](writeups/17-kubeaudit.md)

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

---

*This is a learning environment with intentionally vulnerable configurations. Never deploy these patterns in production.*
