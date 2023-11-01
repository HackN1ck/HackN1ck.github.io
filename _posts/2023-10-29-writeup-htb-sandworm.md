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
  alt: Sandworm
---

> Queridos lectores, es un placer darles la bienvenida a este fascinante viaje a través del mundo de HackTheBox. En esta ocasión, nos sumergiremos en los entresijos de la máquina Sandworm, un reto catalogado como de dificultad media y la cual está alojada en un servidor Linux. En este emocionante recorrido, exploraremos una vulnerabilidad de Server Side Template Injection (SSTI), la cual nos permitiría obtener una user shell, y luego, ganaremos acceso a otro usuario. Como desafío final debemos realizar una escalada de privilegios (privilege escalation) a través de Firejail para obtener el codiciado acceso de root.   

