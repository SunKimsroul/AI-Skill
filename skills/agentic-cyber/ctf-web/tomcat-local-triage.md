# Tomcat CTF Local Triage

Use this workflow only for a supplied CTF source archive, WAR, container image, or organizer-provided local endpoint. Do not probe unrelated Tomcat instances.

## Build a configuration map first

1. Record the Tomcat version from supplied image labels, `catalina.jar`, startup logs, and `ServerInfo.properties`; do not infer it solely from an HTML error page.
2. Unpack supplied WAR files without executing them. Inventory `WEB-INF/web.xml`, `WEB-INF/classes`, `WEB-INF/lib`, `META-INF/context.xml`, static files, and framework configuration.
3. Create a route table from servlet/filter/listener declarations and mappings. Relate each path to its class, auth constraint, error handler, and method restrictions.
4. Inspect the supplied `server.xml`, `context.xml`, `tomcat-users.xml`, and Compose/Docker configuration for connectors, AJP enablement, manager roles, bind addresses, mounted secrets, and container-network relationships.

## Reconstruct the relevant trust boundary locally

1. Diagram each hop: browser or supplied client -> proxy -> application -> Tomcat connector -> filesystem or adjacent container. Note where a redirect, URL parser, authentication header, or host restriction changes meaning.
2. For a proxy-style challenge, reproduce redirects and authentication forwarding against a harmless local fixture. Preserve the exact proxy, application, and Tomcat versions because behavior varies by version and configuration.
3. Treat `WEB-INF/web.xml` and compiled servlet classes as high-value evidence: they can reveal routes and intended inputs that are not linked in the UI. Decompile supplied `.class` files locally and reconcile route mappings with the code.

## Validate only within the challenge environment

1. Run the supplied Compose/image stack on an isolated local network where practical. Use a benign marker file and a dummy application to confirm a suspected route, redirect, connector, or manager configuration before relying on it.
2. Record the version, configuration file hash, request path, response status, and the local service/container that handled the request. A 401, 403, or 404 is evidence about a specific layer, not proof that the endpoint is absent.
3. If a known issue is relevant, confirm the exact affected version and the required local connector/configuration facts before classifying it. Keep the technique description and validation evidence separate.

## Hand-off boundaries

- Use `ctf-reverse` for opaque servlet classes, custom `catalina.jar`, or native helpers.
- Use the supplied local model for CTF solution work; do not convert a local container finding into an external scanning or exploitation workflow.

## Sources

- Insomni'hack 2024 *Jumper*: supplied proxy plus Tomcat containers, manager configuration, and proxy/container boundary analysis: <https://ctftime.org/writeup/39110>
- VolgaCTF 2020 *Netcorp*: supplied Tomcat version identification, `web.xml` route recovery, and servlet-class analysis: <https://ctftime.org/writeup/19248>
