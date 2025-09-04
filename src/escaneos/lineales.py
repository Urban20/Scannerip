'escaneos lineales : -n (normales), -p (selectivos)'

import socket
import logging
from func import preg_informe,puertos
import time
from colorama import Fore
import data
import archivos.archivos
from platform import system
if system() == 'Windows':
    from keyboard import is_pressed
import params


puertos_escaneados = 0 # contador --> lleva un conteo de puertos escaneados al escanear con un escaneo normal de handshake completo
ips_encontradas = 0 # contador --> cuenta la cantidad de ips encontradas, cuando es mayor al arg de buscar, detiene la funcion de busqueda
deten = False   


def mecanismo_detener():
    '''
    pequeña funcion que maneja la escucha de la tecla escape para detener el funcionamiento en escaneos sin multihilos
    * relacionada a funcion detener( )
    * se utiliza en Windows'''

    if is_pressed('esc'): #se activa cuando se detecta la tecla ESC
        print(Fore.RED+'[+] deteniendo')
        logging.info('deteniendo herramienta')
        
        return True # retorna boleanos que van a ser interpretados por detener()
    else:
        return False

def detener():
    'funcion que detiene la herramienta en ciertos contextos, tambien maneja el progreso en escaneos normales (porcentaje de carga)'
    global puertos_escaneados,ips_encontradas,deten
    tamaño_list_i = len(puertos)
    tiempo = time.time()
    if params.param.buscar == None:
        while not deten:
            
            try:
                if system() == 'Windows':
                    deten = mecanismo_detener()
                else: deten = False

            except AttributeError:
                pass

            finally:
                # maneja el porcentaje de la carga de escaneos normales
                val_prog = (puertos_escaneados/tamaño_list_i) * 100
                porcentaje =f'{str(val_prog)[:5]}%'
                    
                if time.time() - tiempo > 5:
                    print(Fore.CYAN+f'[*] progreso: {porcentaje}')
                    tiempo = time.time()
                if porcentaje == '100.0%' or deten:
                    print(Fore.GREEN+'\n[+] escaneo finalizado\n')
                    logging.info('deteniendo herramienta')
                    deten= True
            
    else:
        try: #aplica para la busqueda de ips publicas, escucha en la techa ESC para ver si se detiene la funcion de busqueda
            while not deten and ips_encontradas < params.param.buscar:
                
                deten = mecanismo_detener()
                
        except AttributeError:
            logging.warning('pequeño error en funcion detener')

def cuerpo_scan(lista,ip,timeout,json_):
    'escaneos de tipo lineal (sin hilos) en protocolos TCP y para ipv4 unicamente'
    
    #para el escaneo selectivo y normal: este es el formato para estos dos tipos de escaneos
    global puertos_escaneados
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
            except socket.gaierror:
                logging.error(f'error en funcion cuerpo_escan')
                deten = True
            except ConnectionRefusedError:
                logging.warning(f'error pequeño en cuerpo_scan')
                pass
           
            except Exception:
                logging.error(f'ocurrio un error en cuerpo_scan')
                
            finally:
                s.close()
                puertos_escaneados+=1

        else:
            break

def scan_selectivo(ip,timeout,puertos):
    logging.info('iniciando escaneo selectivo...')
    data_p = archivos.archivos.cargar_json('data_puertos.json')
    eleccion = list(puertos.split(','))
    cuerpo_scan(ip=ip,lista=eleccion,timeout=timeout,json_=data_p)
    if not data.p_abiertos:
        print(Fore.RED+'\nningun puerto encontrado\n')

def scan_normal(ip,timeout,hilo): 
    'inicia el escaneo normal (escaneo lineal basado en latencias)'
    
    logging.info('iniciando escaneo normal...')
    dato = archivos.archivos.cargar_json('data_puertos.json')
    print(Fore.WHITE+f'[+] escaneando puertos TCP de la ip: {ip}')
    try:
            
        cuerpo_scan(ip=ip,timeout=timeout,lista=puertos,json_=dato)

       
    except Exception as e:
        logging.critical('ocurrio un error inesperado en el escaneo normal')
        
    finally:
        time.sleep(1)
        hilo.join() # para que no se pise el input con la carga
        preg_informe()