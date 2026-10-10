# Bash CGI Environment-Import Triage

**Scope:** Use only for an explicitly supplied CTF target or an identical local container. This note is for recognizing and reproducing the historical Bash function-import defect (Shellshock/CVE-2014-6271) in a controlled challenge environment; do not test arbitrary public CGI endpoints.

## Recognize the Boundary

Look for a legacy CGI route, an executable script invoked through a web server, Bash in the supplied source/container, and a request header or CGI variable that reaches the script environment. The defect is relevant only when a vulnerable Bash parses an environment value as a function definition during startup and then processes trailing content. A CGI path alone is not evidence.

## CTF-Local Workflow

1. **Map the route from supplied evidence.** Use challenge source, container files, or a named route to establish which handler is CGI and which interpreter launches it. Do not infer Bash from a web-server banner.
2. **Map request input to environment.** In the local container, log the CGI environment for one normal request. Record which header/parameter becomes which `HTTP_*` or CGI variable and whether an intermediary rewrites it.
3. **Fingerprint the actual interpreter.** Capture the Bash version and the script shebang or process command. A patched Bash or a non-Bash CGI script rules out this path.
4. **Use a harmless local marker.** Reproduce the environment-import behavior only in the supplied container with a non-destructive marker whose sole expected result is an explicitly observable response difference. Keep the normal CGI output as a control.
5. **Prove scope and effect.** Repeat the marker with the mapped and unmapped variables, and preserve request/response evidence. If the challenge requires a file artifact, retrieve only the explicitly named CTF artifact after the local proof is stable.

## Validation and Failure Modes

- A `200` response, a CGI route, or the string `bash` in a comment is not a proof.
- Header-to-environment translation is server-specific; test it locally before concluding that a request reaches Bash.
- Different Bash patch levels can change parser behavior. Preserve the exact image/version with the result.
- Treat unexpected network, process, or filesystem side effects as a stop condition; the intended CTF proof should be minimal and reproducible.

**Source patterns:** Inferno CTF 2019, `We will we will Shock You` ([writeup metadata](https://ctftime.org/writeup/17790)); AUCTF 2020, `M1 Abrams` ([writeup metadata](https://ctftime.org/writeup/19664)).
