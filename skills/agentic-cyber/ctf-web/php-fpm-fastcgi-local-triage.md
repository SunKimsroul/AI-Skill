# PHP-FPM / FastCGI Local Triage

Use this note for a supplied PHP application, web-server configuration, container, or local CTF stack that uses PHP-FPM. The objective is to reconstruct the application-to-FPM boundary from artifacts and harmless local tests. Do not send handcrafted FastCGI records to a service outside the supplied CTF or authorized lab.

## Establish the boundary

1. Record the exact PHP, PHP-FPM, and front-end server versions from the supplied image, lockfiles, package metadata, and startup scripts.
2. Find each `fastcgi_pass` or equivalent directive and preserve its context: UNIX-socket or TCP endpoint, pool name, route/location matcher, included parameter files, document root, script filename construction, and network namespace/container boundary.
3. Trace every referenced pool file such as `www.conf`. Record `listen`, socket owner/group/mode, process user/group, `clear_env`, `security.limit_extensions`, `open_basedir`, disabled functions, and `php_admin_value` / `php_value` settings. Do not assume a setting from a front-end config overrides a pool-level administrative value.

## Map execution provenance

1. Starting at the supplied request route, map front-end location rule -> included FastCGI parameters -> resolved script path -> PHP-FPM pool -> effective PHP configuration. Keep source file paths and line references for each edge.
2. Determine whether the front end can reach the FPM listener only through the normal local socket/loopback path, and whether socket permissions or container networking create a separate trust boundary.
3. Treat any discrepancy between a web-server policy and FPM policy as a configuration finding. Do not equate a reachable listener with authority to invoke arbitrary scripts.

## Harmless local validation

1. In an isolated copy of the supplied stack, add a non-sensitive marker script within the documented application root. Request it through the intended local route and save the response status plus the relevant front-end and FPM logs.
2. Compare one controlled configuration variable at a time (for example, production versus development environment) and confirm its observed effect with a marker value. Never use production credentials, flags, or files outside the supplied artifact as test inputs.
3. Restore the copied configuration and repeat the known-good request. Record the versions, listener kind, path-resolution chain, and result so a teammate can reproduce it.

## Handoff

Report listener type/location, pool ownership and access boundaries, path-resolution evidence, effective configuration precedence, and the harmless test result. If a conclusion relies on an assumed runtime value, mark it as unverified until it is demonstrated in the supplied local stack.

## Sources

- [hxp CTF 2020 — resonator](https://ctftime.org/writeup/25660) (FastCGI listener transport as a challenge trust boundary)
- [hxp CTF 2020 — heiko](https://ctftime.org/writeup/25659) (FPM pool configuration and PHP runtime constraints)
