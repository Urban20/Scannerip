#! /usr/bin/env -S python3
'''codigo fuente del programa:
* llama todas las funciones y modulos necesarios para la ejecucion del mismo'''

import threading
from func import *
from colorama import init,Fore
from params import *
from data import *
from objetos import *
from concurrent.futures import ThreadPoolExecutor
from platform import system
from logging import info,critical
from scapy_escan import *
import subprocess as sp
from os import devnull
import sys
import gopy

# Cree esta herramienta con el objetivo de obtener informacion rapida de las direcciones IP
# Pensado en un inicio para windows pero compatible a Linux y con mejoras para este
# Intento mejorar y mantener el codigo dentro de lo posible

# Nota: el codigo probablemente funcione mejor en entornos Linux aunque es compatible tambien en Windows
# El codigo puede modificarse libremente e incluso estoy abierto a contribuciones
# Autor: Urb@n (Urban20, Matias Urbaneja)

def inicio_scan(msg):
    '''
    funcion de inicio de escaneos normales o selectivos
    * maneja las latencias y el timeout
    * solo se llama cuando son escaneos normales o selectivos
    ''' 
    print(Fore.WHITE+f'\n\n#################################################')
    print(Fore.WHITE+msg)
    if system() == 'Windows':
        print('\n[+] "esc" para salir\n')
    if param.timeout == None:
        lat_prom= latencia(param.ip)
        tim = timeout(lat_prom)
    else:
        tim = param.timeout
    print(f'[+] timeout: {tim}')
    return tim

#revisa si se trata de un usuario root o no
if system() == 'Linux':

    usuario =sp.check_output('whoami',text=True).lower().strip()
else:
    usuario = None



def crear_crawler(ip_):
    '''
    crea el objeto crawler
    * solo se llama al realizar OSINT con shodan'''

    info('creando objeto crawler...')
    
    print(Fore.RED+'\n[+] iniciando crawler')
    
    #ip_num = ip numerica
    ip_num = ip.validacion(ip_)
    ip.informacion()
    ip.reputacion()

    #crawler
    crawler = Bot_Crawler(ip=ip_num)
    crawler.scrapping_shodan()
    crawler.obtener_links()

# hilos por defecto
if param.hilo == None:
    hilo_= 100
else:
    hilo_ = param.hilo


def main():
    if param.shodan:
        
        if param.ip != None:
            
            for x in param.ip.split(','):
                try:
                    crear_crawler(ip_=x)  

                except AttributeError:
                    print(Fore.RED+'\n[+] sin informacion al respecto\033[0m\n')
                    continue
            
        else:
            print(Fore.RED+'[+] especificar argumento [-ip]')   
        
    if param.agresivo:

         #t es el timeout para los escaneos agresivos
        if param.timeout == None:
            t = 0.5
        else:
            t = param.timeout

        if param.ip != None:
            print(Fore.WHITE+'''\n\n#################################################''')
            info('escaneo agresivo iniciado...')
            print(Fore.WHITE+'[+] escaneo agresivo en curso...')
            gopy.go_agresivo(param.ip)
            if param.info:
                for puerto in gopy.leer_puertos_go():
                    informacion(ip=param.ip,puerto=int(puerto)) 
                      
   
        else:
            print(Fore.RED+'\n[+] especificar argumento [-ip]\n')        
    
    #escaneo SYN
    elif param.syn and param.ip != None:
        if system() == 'Linux':
            if usuario == 'root':
                if param.masivo:
                    print(Fore.YELLOW+'\n[+] escaneando todos los puertos...\n')
                info('se inicia proceso de escaneo syn...')
                print(Fore.WHITE+'\n[+] escaneo syn en curso ...\n')
                if param.timeout != None:
                    t = param.timeout
                else:
                    print('\n[+] timeout calculado automaticamente\n')
                    latencia_ = latencia(param.ip)
                    t = timeout(latencia_)
                for p in puertos:
                    proceso =escaneo_syn(ip=param.ip,puerto=p,timeout=t)

            else:
                raise PermissionError
                      
        else:
            print(Fore.RED+'\n[+] escaneos syn:\n[+] funcion exclusiva de Linux\n')

    #escaneo normal
    elif param.normal and param.buscar == None:
        if param.ip != None:
            
            scan= inicio_scan(msg='escaneo normal en curso...')
            
            carga= threading.Thread(target=detener) # hilo que maneja la carga y la detencion (detencion solo en win)
            carga.start()
            
            scan_normal(param.ip,scan,carga)   
            
        else:
            print(Fore.RED+'[+] especificar argumento [-ip]') 

    #escaneo selectivo
    elif param.selectivo:
        if param.ip != None:
            
        
            scan= inicio_scan(msg='[+] escaneo selectivo en curso...')

            scan_selectivo(param.ip,scan,param.selectivo)
            
        else:
            print(Fore.RED+'\n[+] especificar argumento [-ip]\n')
    
    #para descubrir ips privadas
    elif param.descubrir:
        
        if param.timeout != None:
            timeout_ = param.timeout
        else:
            timeout_ = 1
    
        print(Fore.GREEN+'[+] rastreando ips privadas:\n')
        
        with ThreadPoolExecutor(max_workers=150) as ejec:

            # se obtiene la direccion ipv4 de la maquina que lleva la operacion
            s_udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s_udp.connect(('10.255.255.255',1))
            ipv4_propia = s_udp.getsockname()[0]

            for ip in ipaddress.ip_network(param.ip):
               
                ejec.submit(descubrir_red,str(ip),timeout_,ipv4_propia) 
               
        if system() == 'Linux':
            for ip in ipv4:
            
                ipv4 = Ipv4(ip=ip)
                codigo = ipv4.ttl()
                nombre = ipv4.obtener_nombre()
                mac  = ipv4.obtener_mac()
                compania = ipv4.obtener_compania()
                json = cargar_json('ttl.json')
                if codigo != None:
                    print(Fore.GREEN+f'\n{ip}:\n')
                    print(json.get(str(codigo)))
                    print(f'\033[0m[*] nombre de disp. en la red: {nombre}')
                    if mac != None:
                        print(f'\033[0m[*] direccion mac: {mac}')
                    if compania != None:
                        print(f'\033[0m[*] compania encontrada: {compania}')
                    print('\n')
                
        
        #buscar ips publicas
    elif param.buscar != None and not param.normal and param.ip == None:
        info('iniciando busqueda de ips publicas...')
        print(Fore.GREEN+'\n[+] rastreando ips publicas...\n')

        if system() == 'Windows': # llama a detener solo en windows para asegurar compatibilidad en Termux (android)

            threading.Thread(target=detener).start() #llama a la funcion detener encargada de monitoriar la presion de escape
            print('\n\033[0m[+] "esc" para salir de la busqueda\n')

        while func.ips_encontradas < param.buscar and not func.deten:
            
            busq = buscar()
            
            if busq != None:
                print(Fore.WHITE+busq)
                func.ips_encontradas+=1
            
        if not param.guardar:
            if str(input(Fore.WHITE+'[1] guardar informacion >> ')).strip() == '1':
                for ip in lista_ips:
                    agregar_arch(ip)
                print(Fore.GREEN+'\n[+] la informacion fue guardada\033[0m\n')

            else:
                print(Fore.RED+'\n[+] la informacion no fue guardada\033[0m\n')

        info('busqueda finalizada')    

        func.deten = True

    if param.info and p_abiertos:
        for x in p_abiertos:
            informacion(param.ip,int(x))

    if param.ayuda:
        ayuda()

    if param.borrar:
        borrar_arch()

    elif param.abrir:
        abrir_arch(nombre_b)

    if param.lectura:
        abrir_arch(nombre_arch)     



if __name__ == '__main__':

    try:
        sys.stderr = open(devnull,'w')
        init()
    #acciones de los parametros-----------------
        main()

    except PermissionError:
        print(Fore.RED+'\n[*] no soy root\n')
        
    except Exception as e:
        print(Fore.RED+f'{e}\n')
        critical(f'error critico desconocido en el flujo principal')
        
    finally:
        
        sys.exit(0)
        