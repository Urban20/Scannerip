'''este modulo contiene las principales funciones que se utilizan en la herramienta
funciones:
- ayuda()
- rastreo()
- latencia()
- timeout()
- descubrir_red()'''

import requests
from colorama import Fore,init
import ipaddress
from random import randint
import params 
import data 
from bs4 import BeautifulSoup
from ping3 import ping
from threading import *
import logging
from escaneos.scapy_escan import *
import archivos.archivos
import fingerprint


# ----- configuracion de log -----
log = 'registro.log'
fecha_fmt = '%a, %d %b %Y %H:%M:%S'


print(f'\n[*] log >> {archivos.archivos.op}, entrar a opciones.json para modificarlo\n')

logging.basicConfig(filename=log, # maneja el formato del archivo log
                        level=archivos.archivos.nivel,
                        datefmt=fecha_fmt,
                        format='%(asctime)s-%(msg)s')

# ----- configuracion de log -----

#opciones del arg -M
if params.param.masivo:
    
    puertos = list(range(1,65535))

else:
    puertos = list(archivos.archivos.cargar_json('puertos.json')['lista'])


def preg_informe():
    'pregunta acerca de guardar informes'
    preg = str(input(Fore.WHITE+'[1] guardar informe >> ').strip())
    if preg == '1':
        titulo = str(input('titulo: '))
        logging.info('guardando informe...')
        archivos.archivos.crear_informe(params.param.ip,data.p_abiertos,titulo)
     
def ayuda():
    'abre panel de ayuda con el argumento -h'

    h = Fore.WHITE+'''
Scip (Scannerip) es una herramienta de reconocimiento de redes desarrollada por Urb@n (Matias Urbaneja) con busqueda en shodan (OSINT de ips publicas) , escaneo de puertos, entre otras cosas

argumentos:
  
\033[31mPARAMETRO/S PRINCIPAL/ES:\033[0m

  -h, --ayuda                              *muestra este mensaje

  -ip IP, --ip IP                          *ip objetivo para el ataque \033[33m(se necesita la mayoria del tiempo)\033[0m

\033[31mOSINT:\033[0m

  -s, --shodan                             *busqueda automatica en shodan

\033[31mTIPOS DE ESCANEOS:\033[0m

  -n, --normal                             *escaneo de puertos con el metodo normal

  -a, --agresivo                           *escaneo agresivo: escanea todos los puertos en simultaneo
                                            Desventaja/s: puede fallar
                                            Ventaja/s: extremadamente rapido
  -p SELECTIVO, --selectivo SELECTIVO      *para escanear puertos puntuales

  --syn                                    *escaneos de handsake incompleto:
                                             - escaneo rapido
                                             - escaneo mas silencioso
                                             - permite ver puertos filtrados 
                                             (solo linux, requiere sudo)

\033[31mARGUMENTOS OPCIONALES (acompañan a los demas argumentos):\033[0m

  -V6                                      *fuerza el uso de ipv6 cuando se hace OSINT

  -M, --masivo                             *Uso: este argumento se combina con los parametros -a y -n
                                            funcion: escanea TODOS los puertos existentes. 
                                            Desventaja/s: escaneo mucho mas lento, puede ser de alta carga para el pc si se lo combina con -a
                                            Ventaja/s: permite escanear todos los puertos

  -g, --guardar                            *Uso: este argumento se combina con el argumento -b
                                            funcion: guardar ips en lista   

  -t, --timeout                            *setea un timeout especifico cuando se utiliza el argumento -n

  -hl, --hilo                              *se utiliza con -a 
                                            setea la cantidad de hilos en paralelo (16 hilos por defecto)

  -i, --info                               *Uso: este argumento se combina con -a y -n
                                           funcion: muestra informacion de los encabezados en caso de encontrarse un puerto que apunta a un html

  -r, --reintento                          * argumento para escaneos syn, setea el numeros de reintentos para recibir informacion de un puerto  
        
  -no_filtrado                             * muestra unicamente los puertos abiertos durante el escaneo syn 

\033[31mARGUMENTOS PARA EL MANEJO DE ARCHIVOS:\033[0m

  -g, --guardar                            *Uso: este argumento se combina con el argumento -b
                                           funcion: guardar ips en lista

  -l, --lectura                            *lee el archivo .txt donde el usuario guarda las ips escaneadas y muestra su contenido

  -cls, --borrar                           *borra el contenido del archivo .txt donde se guardan las ips encontradas
 
  -abrir, --abrir                          *lee el archivo .txt donde se guardan las ips encontradas
    
\033[31mARGUMENTOS DE BUSQUEDAS DE IPS:\033[0m

  -b BUSCAR, --buscar BUSCA                *Uso: este argumento se utiliza solo, su uso es -b [numero]
                                            funcion: busqueda de ips, puede utilizarse junto con -g para guardar

  -d, --descubrir                          *se utiliza para descubrir ips privadas dentro de la red.
                                            ejemplo de uso:
                                           -ip 192.168.0.0/24 -d (siendo "-d" el argumento para usar la funcion)
                            
                                                   
 \033[33mNOTA : la herramienta no es capaz de escanear puertos ipv6 por el momento, ademas solo se tienen en cuenta protocolos TCP\033[0m       '''

    
    print(f'\n{data.logo}')
    print(Fore.CYAN+'github: https://github.com/Urban20')
    print(f'{h}\n')
    
def informacion(ip,puerto):
    'esta funcion es la que gestiona la informacion que proviene de fingerprint y en base a los resultados da un mensaje en consola'
    
    print(Fore.CYAN+f'\n[*] se intenta obtener informacion en el puerto {puerto} ...\n')
    fing= fingerprint.fingerprint(ip,puerto)
    

    print(Fore.WHITE+f'''
#################################################
puerto:{puerto}\n\r\n\r* respuesta del servidor:\n''')
    if fing != None and fing != '':
        print(f'\n{fing}\n')
    
    else:
        print(Fore.RED+'[X] sin informacion, no se recibio respuesta\n')

    print(Fore.WHITE+'#################################################') 

def confiabilidad_ip(ip):
    'consulta si una direccion ip es confiable o esta en lista negra'
    url = 'https://barracudacentral.org/lookups/lookup-reputation'
    if requests.get(url).status_code == 200:
        print(Fore.WHITE+'\n[*] confiabilidad de la ip:')
        try:
            dir_ = ipaddress.ip_address(ip) 

            if dir_.is_global:
                valores = []
                
                with requests.session() as s:

                    html = BeautifulSoup(s.get(url).text,'html.parser')

                    for x in html.find_all('input'):
                        
                        valores.append(x.get('value'))
                    key = str(valores[1])


                    datos_post ={'lookup_entry':ip,
                            'submit':'Check Reputation',
                            'cid':key}
                    
                    
                    for i in ['success-message','failure-message']:
                        try:
                            html_post= BeautifulSoup(s.post(url,data=datos_post).text,'html.parser')

                            html_post.find('p',class_=i).text.strip()
                            return i
                        except AttributeError:
                            continue
            else:
                return 'no valida'
        except  ValueError:
            return 'no valida' 

def rastreo(url,json_):
    'envia peticiones a urls expuestas al hacer OSINT a una ip con shodan'
    logging.info('iniciando rastreo...')
    try:
        datos = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'}
        solicitud= requests.get(url,timeout=5,headers=datos)
        if solicitud.status_code == 200:
            return Fore.GREEN+'* responde'
            
        else:
            return Fore.YELLOW+f'* {json_.get(str(solicitud.status_code))}'
    
    except requests.Timeout:
        return Fore.RED+'* no responde: tiempo agotado'
    except Exception :
        return Fore.RED+'* no responde'

def latencia(ip):
    'hace ping 3 veces y devuelve el promedio de las latencias'

    try:
        
        ping_ = 0
        for i in range(3):
            ping_+=ping(ip,timeout=1)    
        return ping_/3
    
    except TypeError:
        return 1
     
def buscar(deten : bool):
    'funcion responsable de la busqueda de direcciones IPV4 publicas (solo ipv4s)'

    
    try:
        elementos=[]
        
        for x in range(4):
            elementos.append(str(randint(0,255)))

        ip = ipaddress.ip_address('.'.join(elementos))
        if ip.is_global:
            geo= requests.get(f'https://api.ip2location.io/?ip={ip}').json()
            shodan= requests.get(f'https://internetdb.shodan.io/{ip}').json()
        
            if list(shodan['ports']):

                info_b= f'''
    ip: {geo['ip']}
    pais: {geo['country_name']}
    estado/prov: {geo['region_name']}
    puertos: {shodan['ports']}

    '''         
                data.lista_ips.append(info_b)

            if params.param.guardar:      
                archivos.archivos.agregar_arch(info_b)

            return info_b
    except KeyError: pass

    except Exception as e:
        logging.error('error inesperado')
        deten = True
        
def timeout(latencia_prom):
    'recibe una latencia y en base a eso calcula un tiempo de espera entre puerto y puerto cuando se usan escaneos lineales'

    logging.info('seteando timeout...')
    print(f'[*] latencia promedio:{latencia_prom} seg')
    #para redes relativamente rapidas
    if latencia_prom >= 0.015 and latencia_prom <= 0.3:
        timeout = latencia_prom * 2
    #para redes muy lentas
    elif latencia_prom > 0.3:
        timeout = latencia_prom * 1.5
    else:
        #timeout minimo para redes locales
        timeout = 0.1
    return timeout

ipv4= []
lock = Lock()  
def descubrir_red(ip,timeout,mi_ipv4):
    'descubre direcciones ipv4 dentro de la red local'

    logging.info('descubriendo la red...')
    
    ping_=ping(ip,timeout=timeout)
    if ping_ != None and ping_ != False:           
        if ip == mi_ipv4:
            print(Fore.YELLOW+ip + ' (este dispositivo)')
        else:
            print(Fore.WHITE+ip)
            with lock:
                ipv4.append(ip)
