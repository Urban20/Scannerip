import requests
from colorama import Fore,init
import socket
import ipaddress
from random import randint
import params 
import data 
import time
from bs4 import BeautifulSoup
from ping3 import ping
from threading import Lock
from platform import system
import json
import logging
from scapy_escan import *
if system() == 'Windows':
    import keyboard


'este modulo contiene las funciones que se utilizan en el script'



#cargar las opciones del log
try:
    with open('opciones.json','r') as opciones:
        cont_op = json.load(opciones)
except:
    print(Fore.RED+'\ncofiguracion incorrecta, revisar opciones.json\n')
    exit(1) 

op = cont_op['nivel']

match cont_op['nivel']:
    case 'basico':
        nivel = logging.WARNING
    case 'detallado':
        nivel = logging.INFO
    case _:
        print(Fore.RED+'\ncofiguracion incorrecta, revisar opciones.json\n')
        exit(1)

#nombre del archivo que se crea al guardar una ip escaneada
nombre_arch = cont_op['arch-guardado-de-puertos']

#nombre del archivo donde se guardan las ips encontradas
nombre_b= cont_op['arch-ips-encontradas']

print(f'\n[*] log >> {op}, entrar a opciones.json para modificarlo\n')

logging.basicConfig(filename='registro.log',
                    level=nivel,
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    format='%(asctime)s-%(msg)s')
                    


logging.warning('iniciando ejecucion de la herramienta...')
init()
deten = False   
# q  contador --> lleva un conteo de puertos escaneados al escanear con un escaneo normal de handshake completo
q = 0
# n contador --> cuenta la cantidad de ips encontradas, cuando es mayor al parametro de buscar, detiene la funcion de busqueda
n = 0

def cargar_json(archivo):
    try:
        logging.info('cargando json...')
        with open(f'json/{archivo}','r') as arch:
            #retorna el diccionario
            return json.load(arch)
    except Exception as e:
        logging.critical(f'error en la carga de uno o varios archivos JSON')

#opciones del parametro -m
if params.param.masivo:
    
    puertos = list(range(1,65535))

else:
    puertos = list(cargar_json('puertos.json')['lista'])

def fingerprint(ip,puerto):
    logging.info('iniciando fingerprint...')
    buffer = 1024
    msg = None
    dic = None
    for x in ['https','http']:
        
        try: 
            dic=dict(requests.get(f'{x}://{ip}:{str(puerto)}',timeout=5).headers)
            break
        except:
            dic = None
            continue
        
    if dic == None:
        try:
            s = socket.socket()

            s.settimeout(1.5)
            if s.connect_ex((ip,puerto)) == 0:
                for x in [b'\x00',b'\x90' * 16,b'\x00\xff\x00\xff',b'USER anonymous\r\n',b'\x10\x20\x30\x40',b'test\r\n', b'\x01\x02\x03', b'GET / HTTP/1.1\r\n\r\n', b'\xff\xff\xff\xff']:
                    try:
                        s.send(x)
                        msg = s.recv(buffer)
                        if msg == b'':
                            raise Exception
                        else: break
                        
                    except TimeoutError: msg = None
                        
                    except:continue

                if msg != None:  
                    return msg.decode()
                
      
        except UnicodeDecodeError: return str(msg)

        finally: s.close()
    else:
        try:
            encabezado = ''
            for x in dic:
                encabezado += f'{x}: {dic[x]}\n\r'
            return encabezado
        except:
            return None
    logging.info('se finalizo el fingerprint')

def preg_informe():
    
    preg = str(input(Fore.WHITE+'[1] guardar informe >> ').strip())
    if preg == '1':
        titulo = str(input('titulo: '))
        logging.info('guardando informe...')
        crear_informe(params.param.ip,data.p_abiertos,titulo)

def cuerpo_scan(lista,ip,timeout,json_):
    
    #para el escaneo selectivo y normal: este es el formato para estos dos tipos de escaneos
    global q
    # q solo se utiliza con normal, es un numero el cual se incrementa con cada puerto escaneado
    global deten

    for x in lista:
        if not deten:
            s = socket.socket()
                    
            s.settimeout(timeout)

            try:
                if s.connect_ex((ip,int(x))) == 0:

                    print(Fore.GREEN+f'[*] puerto abierto >> {x}')

                    print(f'uso mas comun: {json_[str(x)]}')
                    data.p_abiertos.append(int(x))
            except KeyError:
                print(f'uso mas comun: [desconocido]')
                data.p_abiertos.append(int(x))
            
            except PermissionError:
                
                continue  
            except socket.gaierror as e:
                logging.error(f'error en funcion cuerpo_escan')
                deten = True
            except ConnectionRefusedError as e:
                logging.warning(f'error pequeño en cuerpo_scan')
                pass
           
            except Exception as e:
                logging.error(f'ocurrio un error en cuerpo_scan')
                
            finally:
                s.close()
                q+=1

        else:
            break

def abrir_arch(txt):
    logging.info('iniciando lectura de archivo...')
    try:
        with open(txt,'r') as arch:
            print(arch.read())
        
    except FileNotFoundError:
        logging.error('no se pudo encontrar el archivo')
    except Exception as e:
        logging.critical(f'hubo un error en la apertura de un archivo')

def borrar_arch():
    try:
        with open(nombre_b,'w') as arch:
            arch.write('')
        print(Fore.GREEN+f'\n[*] archivo borrado: {nombre_b}\n')
        logging.info('se elimino el contenido del registro d eips encontradas')
    except:
        logging.error('hubo un error en borrar_arch')
        
def ayuda():
    
    h = Fore.WHITE+'''
scip es una herramienta de reconocimiento de redes desarrollada por Urb@n con busqueda en shodan y escaneo de redes, entre otras cosas

parametros:
  -h, --ayuda                             *muestra este mensaje

  -s, --shodan                            *busqueda automatica en shodan

  -n, --normal                            *escaneo de puertos con el metodo normal

  -a, --agresivo                          *escaneo agresivo: escanea todos los puertos en simultaneo
                                            Desventaja/s: puede fallar
                                            Ventaja/s: extremadamente rapido

  -p SELECTIVO, --selectivo SELECTIVO     *para escanear puertos puntuales

  -ip IP, --ip IP                         *ip objetivo para el ataque

  -b BUSCAR, --buscar BUSCA               *Uso: este parametro se utiliza solo, su uso es -b [numero]
                                           funcion: busqueda de ips, puede utilizarse junto con -g para guardar

  -g, --guardar                           *Uso: este parametro se combina con el parametro -b
                                           funcion: guardar ips en lista

  -i, --info                              *Uso: este parametro se combina con -a y -n
                                           funcion: muestra informacion de los encabezados en caso de encontrarse un puerto que apunta a un html

  -l, --lectura                           *lee el archivo .txt donde el usuario guarda las ips escaneadas y muestra su contenido

  -t, --timeout                           *setea un timeout especifico cuando se utiliza el parametro -n

  -m, --masivo                            *Uso: este parametro se combina con los parametros -a y -n
                                           funcion: escanea TODOS los puertos existentes. 
                                           Desventaja/s: escaneo mucho mas lento, puede ser de alta carga para el pc si se lo combina con -a
                                           Ventaja/s: permite escanear todos los puertos

  -cls, --borrar                           *borra el contenido del archivo .txt donde se guardan las ips encontradas
 
  -abrir, --abrir                          *lee el archivo .txt donde se guardan las ips encontradas
    
  -d, --descubrir                          *se utiliza para descubrir ips privadas dentro de la red.
                                            ejemplo de uso:
                                           -ip 192.168.0.x (ip con "x" para buscar variaciones de la ip en ese sitio) -d (parametro para usar la funcion) 
    
  -hl, --hilo                              *se utiliza con -a 
                                            setea la cantidad de hilos en paralelo (16 hilos por defecto)
                                                
  -r, --reintento                          * parametro para escaneos syn, setea el numeros de reintentos para recibir informacion de un puerto  
        
  -no_filtrado                             * muestra unicamente los puertos abiertos durante el escaneo syn                 '''

    
    print(f'\n{data.logo}')
    print(Fore.CYAN+'github: https://github.com/Urban20')
    print(f'{h}\n')
    

def informacion(ip,puerto):
    #esta funcion es la que gestiona la informacion que proviene de fingerprint y en base a los resultados da un mensaje en consola
    
    print(Fore.CYAN+f'\n[*] se intenta obtener informacion en el puerto {puerto} ...\n')
    fing= fingerprint(ip,puerto)
    

    print(Fore.WHITE+f'''
#################################################
puerto:{puerto}\n\r\n\r* respuesta del servidor:\n''')
    if fing != None and fing != '':
        print(f'\033[1;32m{fing}')
    
    else:
        print(Fore.RED+'[X] sin informacion, no se recibio respuesta\n')

    print(Fore.WHITE+'#################################################') 

def confiabilidad_ip(ip):
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

def crear_informe(ip,puerto,titulo):
    logging.info('creando informe...')
    try:
        informe=f'''
##############################
titulo : {titulo}
ip: {ip}

puertos por defecto abiertos:
{puerto}
##############################
        '''


        with open(nombre_arch,'a') as arch:
            arch.write(informe)
    except Exception as e:
        logging.critical('ocurrio un error en la creacion del informe')

def detener():
    global q,n,deten
   
    tamaño_list_i = len(puertos)
    tiempo = time.time()
    if params.param.buscar == None:
        while not deten:
            
            try:
                if system() == 'Windows':
                    if keyboard.is_pressed('esc'):
                        print(Fore.RED+'[*] deteniendo')
                        
                        deten = True
            except AttributeError:
                pass

            finally:
                
                val_prog = (q/tamaño_list_i) * 100
                porcentaje =f'{str(val_prog)[:5]}%'
                    
                if time.time() - tiempo > 5:
                    print(Fore.CYAN+f'[*] progreso: {porcentaje}')
                    tiempo = time.time()
                if porcentaje == '100.0%' or deten:
                    print(Fore.GREEN+'\n[+] escaneo finalizado\n')
                    logging.info('deteniendo herramienta')
                    deten= True
            
    else:
        try:
            
                while n < params.param.buscar and not deten and system() == 'Windows':
                    if keyboard.is_pressed('esc'):
                        print(Fore.RED+'[+] deteniendo')
                        logging.info('deteniendo herramienta')
                        deten = True
        except AttributeError:
            logging.warning('pequeño error en funcion detener')

def latencia(ip):
    try:
        latencias = []
        ping_ = 0

        for i in range(3):
            latencias.append(ping(ip,timeout=1))
        
        for x in latencias:
            ping_+=x
            
        return ping_/3
    except TypeError:
        return 1
    
def scan_normal(ip,timeout):
    logging.info('iniciando escaneo normal...')
    dato = cargar_json('data_puertos.json')
    print(Fore.WHITE+f'[+] escaneando puertos TCP de la ip: {ip}')
    try:
            
        cuerpo_scan(ip=ip,timeout=timeout,lista=puertos,json_=dato)

       
    except Exception as e:
        logging.critical('ocurrio un error inesperado en el escaneo normal')

    finally:
        time.sleep(1)   
        preg_informe()
                  
def scan_selectivo(ip,timeout,puertos):
    logging.info('iniciando escaneo selectivo...')
    data_p = cargar_json('data_puertos.json')
    eleccion = list(puertos.split(','))
    cuerpo_scan(ip=ip,lista=eleccion,timeout=timeout,json_=data_p)
    if not data.p_abiertos:
        print(Fore.RED+'\nningun puerto encontrado\n')

def scan_agresivo(ip,puerto,timeout,json_):
    
    
    try:   
        
        s = socket.socket()       
        s.settimeout(timeout)

        try:
            if s.connect_ex((ip.strip(),puerto)) == 0:
                print(Fore.GREEN+f'[*] puerto abierto >> {puerto}\n servicio mas probable: {json_.get(str(puerto))}\n\r')
                with data.cerradura:
                    data.p_abiertos.append(puerto)
            
        except PermissionError:
            pass
        except OSError:
            logging.warning('OSError durante la conexion del socket en scan_agresivo')
                 
        finally:
            s.close()
               
    except ValueError:
        pass
    except: logging.error('error desconocido en scan_agresivo')
         
#la funcion para agregar arhivos, corresponde a buscar
def agregar_arch(datos):
    with open(nombre_b,'a') as ip_lista:
        ip_lista.write(datos)

def buscar():
    global deten
    try:
        elementos=[]
        
        for x in range(4):
            elementos.append(str(randint(0,255)))

        ip = ipaddress.ip_address('.'.join(elementos))
        if ip.is_global:
            geo= requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}').json()
            shodan= requests.get(f'https://internetdb.shodan.io/{ip}').json()
        
            if list(shodan['ports']):

                info_b= f'''
    ip: {geo['geoplugin_request']}
    pais: {geo['geoplugin_countryName']}
    estado/prov: {geo['geoplugin_region']}
    puertos: {shodan['ports']}

    '''         
                data.lista_ips.append(info_b)

            if params.param.guardar:      
                agregar_arch(info_b)

            return info_b
    except KeyError: pass

    except Exception as e:
        logging.error('error inesperado')
        deten = True

def timeout(latencia_prom):
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
def descubrir_red(ip,i,timeout):
    logging.info('descubriendo la red...')
    
    direc = ip.replace('x',str(i))
    ping_=ping(direc,timeout=timeout)
    if ping_ != None and ping_ != False:
        if ipaddress.ip_address(direc).is_private:
            print(Fore.WHITE+direc)
            with lock:
                ipv4.append(direc)
