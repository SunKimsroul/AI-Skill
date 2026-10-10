# Apache Flink JobManager CTF Triage

Use this workflow only for a supplied CTF service or an explicitly authorized lab. Apache Flink's JobManager UI and REST surface are operational interfaces, not ordinary application pages; do not submit jobs, alter cluster state, or probe unrelated paths outside the challenge scope.

## Version-Aware JobManager File-Read Triage (HTB Business CTF 2021)

**Recognition:** An HTTP service on a management-looking port (commonly `8081`) identifies as Apache Flink, exposes a JobManager dashboard, or returns REST responses mentioning jobs, task managers, logs, archives, or configuration. A challenge may pair that service with a web application whose configuration is stored in a local `.env`/settings artifact.

### 1. Separate the two attack surfaces

1. Record the supplied endpoint, visible product/version data, redirects, and exposed UI/REST routes.
2. Determine whether the challenge supplies a Flink image, source revision, or exact release. Inspect that local material first; vendor patches can change endpoint behavior independently of a product banner.
3. Treat the management plane as a different trust boundary from the primary web application. A file-read finding may provide configuration evidence; it does not automatically mean job submission or code execution is in scope.

### 2. Reproduce the file-read behavior locally

In the supplied container, identify the route handler responsible for log/archive/file retrieval and test it against a harmless fixture deliberately placed in the local challenge tree. Capture the normalized path, HTTP status, content type, and resulting local access log.

```bash
# Supplied container/source only: establish provenance before any retrieval.
grep -RniE 'JobManager|archive|log|path.*normaliz|travers' ./challenge-source 2>/dev/null
curl -isS "http://127.0.0.1:8081/" | sed -n '1,30p'
```

Do not turn a path-normalization proof into broad filesystem enumeration. Request only the exact configuration or artifact named by the CTF challenge after the local model is proven.

### 3. Correlate recovered configuration with the intended next surface

If an explicitly scoped configuration file reveals an application endpoint, database name, or service account, verify it against the supplied app source/configuration rather than assuming every secret is live. Maintain an evidence ledger containing the Flink build, request purpose, returned object hash, and the code/config reference that explains its relevance.

### 4. Validate without changing service state

- Reproduce the local read from a clean container.
- Confirm that the retrieved artifact exists at the expected challenge path and matches its configured consumer.
- Avoid JobManager job uploads, cancellation, deletion, or cluster-configuration changes unless the CTF specifically requires them.

**Key insight:** Flink management endpoints have a different filesystem and deployment context from the web application they support. Version provenance plus a local route-handler trace distinguishes a real path-normalization flaw from a dead endpoint or a patched build.

**Source inspiration:** HTB Business CTF 2021, *Level*: <https://ctftime.org/writeup/29625>.
