# Log4j Configuration-Expansion CTFs

Use this note for a supplied Java web challenge with Log4j source/configuration and a local container or organizer endpoint. Do not test logging expressions against production services.

## Start with version and evaluation context

1. Record the exact Log4j and Java versions, plus the application launch arguments.
2. Do not assume an old message-lookup behavior exists. Determine separately whether expansion occurs in a user-controlled log message, a pattern layout, a configuration property, or an exception path.
3. Read the full logging configuration and trace every dynamic field in the layout: environment, system properties, context map values, and command-line properties.

## Turn source into an observable local model

- Identify how input crosses the frontend/backend boundary: argument list, environment variable, system property, context data, or ordinary log message.
- Reproduce one harmless local value through the exact path and capture both client-visible output and local logs.
- If a dynamic configuration field consumes an indirectly controlled value, test its expansion in the provided challenge container first. Keep the test non-destructive and compare the resolved log line to the source layout.
- If only a prefix, error, or timing difference is exposed, model it as a CTF oracle: define the candidate character/state, expected observable result, retry behavior, and an independent local confirmation.

## Common CTF mistakes

- Confusing message lookups with configuration/layout lookups.
- Ignoring application argument quoting and array-to-string conversion before the logger sees the data.
- Treating a configured value as static even though it is resolved after another property expands.
- Assuming a generic historical Log4j technique applies without checking the supplied version and configuration.

## Source-derived pattern

Google CTF 2022's `Log4J`/`Log4J2` challenges used a modern Log4j version where the familiar message lookup route was unavailable. The useful CTF workflow was to trace configuration-time pattern expansion, reproduce it locally, then use the challenge's limited observable output as an oracle.

Sources: <https://sigflag.at/blog/2022/writeup-googlectf2022-log4j/>, <https://intrigus.org/research/2022/07/18/google-ctf-2022-log4j2-writeup/>
