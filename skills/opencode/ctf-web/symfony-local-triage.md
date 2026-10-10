# Symfony Local Triage

Use this note for a supplied Symfony source tree, container, archive, or challenge endpoint that is explicitly in scope. Work from the provided artifacts and a locally started copy; do not use profiler/debug clues to enumerate unrelated public services.

## Preserve the runtime evidence

1. Record the PHP version/SAPI, Symfony version, and dependency lockfile before changing anything. Check `composer.lock`, `composer.json`, the application kernel, and the entry point such as `public/index.php`.
2. Build a route-to-handler map from `config/routes*`, controller attributes/annotations, controllers, middleware/event subscribers, and templates. Keep the source path and revision beside each finding.
3. Capture configuration provenance rather than assuming one environment file wins. Compare real process environment, `.env`, `.env.local`, `.env.<environment>`, `.env.local.php`, framework cache, and container/deployment variables. Treat secret-looking values as evidence to preserve, not values to reuse outside the supplied environment.

## Reconstruct debug and profiler behavior

1. Identify the effective environment and debug setting from the local entry point and runtime configuration. Test production-like and development-like configurations separately; a visible toolbar or detailed exception page does not by itself prove the same behavior in both.
2. Map any profiler, toolbar, exception, or source-path reference back to the exact local configuration, route, controller, and error handler responsible for it. Distinguish a path disclosure from the ability to read a file.
3. Inspect the supplied configuration for custom environment locations, route imports, cache directories, and database/Doctrine wiring. Record precedence and the exact code path that consumes the setting.

## Validate without changing the challenge logic

1. Start the supplied stack in an isolated local environment. Use a harmless, clearly labelled marker in a temporary copy of a template or configuration value to demonstrate which source path and environment are active.
2. Repeat the same local request under the two relevant environment/debug configurations. Save request, response status, exception class, and a short non-secret excerpt that establishes the route-to-runtime relationship.
3. Revert the marker and confirm the original response returns. If a conclusion depends on a cache artifact, clear or rebuild only the local copied cache and record that fact.

## Handoff

Report the application version, effective environment/debug state, route-to-handler chain, configuration precedence, and exact local evidence. Do not turn source paths, credentials, or profiler information into instructions for accessing systems outside the named CTF or authorized lab.

## Sources

- [Securinets CTF 2019 — Custom Location](https://ctftime.org/writeup/14077) (Symfony configuration/debug context)
- [Symfony configuration documentation](https://symfony.com/doc/current/configuration.html)
