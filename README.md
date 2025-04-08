![logo.png](https://github.com/Urban20/escaner-de-red/blob/main/img/logo.png?raw=true)

<p>

  <img alt="Static Badge" src="https://img.shields.io/badge/hecho_en-Python-blue?style=flat-square&logo=python&logoColor=white">
  <img alt="Static Badge" src="https://img.shields.io/badge/Espa%C3%B1ol-yellow%3Fstyle%3Dflat?style=social">
  <img alt="Static Badge" src="https://img.shields.io/badge/integrado_con-shodan-red?style=flat-square">
  <img alt="Static Badge" src="https://img.shields.io/badge/compatible_con-Windows-magenta?style=flat-square&">
  <img alt="Static Badge" src="https://img.shields.io/badge/compatible_con-Linux-green?style=flat-square&logo=linux&logoColor=black">
  <img alt="Static Badge" src="https://img.shields.io/badge/compatible_con-Termux-black?style=flat-square&logo=gnometerminal&logoColor=black">


</p>


### Importante:

antes de ejecutar la herramienta se debe abrir un terminal en el directorio y ejecutar el comando:
`pip install -r requirements.txt`
esto instala todas las librerias necesarias para la ejecucion del codigo

## Escaner de red
scip es una herramienta que integra OSINT para redes informaticas , escaneos de red de forma activa utilizando socket , busquedas de ips de forma aleatorias con sus respectivos puertos y geolocalizacion.
El objetivo de esto es crear una herramienta muy versatil en el campo de las redes informaticas.

## Caracteristicas:

-recopilacion de informacion de una ip (geolocalizacion,isp,region,puertos abiertos registrados por shodan) (ipv4/ipv6)

-tiene varias estrategias para obtener puertos abiertos (por el momento solo es capaz de escanear protocolos TCP y direcciones ipv4)

-descubre ips dentro de una red privada e intenta obtener informacion de los dispositivos conectados ( esta ultima funcion esta disponible en Linux y termux)

-busqueda aleatoria de ips con gran posibilidad de encontrar puertos abiertos


### escaneos de hadshake completo (libreria socket):

-escaner agresivo >> escaneo rapido

-escaner normal >> escaneo mas lento pero en ocaciones mas fiable

-escaner selectivo >> escanea solo los puertos que elijas 

### escaneo de handshake incompleto (solo linux)(requiere sudo):

-escaner syn >> mas silencioso, permite ver que puertos estan filtrados (parametro >> -syn o --syn)

agregar -no_filtrado para mostrar solamente los puertos abiertos

## Uso:

el script se usa en linea de comandos y su escritura es la siguiente:

python scip3.py -ip [ip objetivo] (puede ser un dominio)  [parametro]



### ejemplos:

python scip3.py -ip www.google.com -s ---> esto busca automaticamente en shodan, busca su geolocalizacion y su reputacion

python scip3.py -ip www.google.com -a ---> realiza un escaneo "agresivo". Se trata de un escaneo en multihilo lo cual lo hace muy rapido pero no siempre funciona

python scip3.py -ip www.google.com -n ---> es un escaneo mas lento pero mas fiable, hace ping a la ip y se basa en dicha latencia para regular la velocidad del escaneo, puede usarse con -i para obtener encabezados de paginas web, tambien puede usarse con -t para proporcionar manualmente un timeout

--> para el caso de python scip3.py es igual solo que se reemplaza la palabra scip

python scip3.py -ip www.google.com -syn ---> escaneos syn (solo linux), se puede acompañar de -t y -r

### parametros:
  
![parametros.png](https://github.com/Urban20/escaner-de-red/blob/main/img/parametros.png?raw=true)

> **algunas demostraciones graficas de como se usan algunas funciones que provee la herramienta:**

![demo2.png](https://github.com/Urban20/escaner-de-red/blob/main/img/demo2.png?raw=true)

![demo3.png](https://github.com/Urban20/escaner-de-red/blob/main/img/demo3.png?raw=true)

> [!WARNING]
no se recomienda poner un numero muy alto para el parametro b ya que esta funcion consume APIS con un numero finito de solicitudes por minuto, si se excede el limite se debe esperar una hora para que tu ip sea desbloqueada