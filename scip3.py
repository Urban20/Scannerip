#! /usr/bin/env python3

import threading
from func import *
from colorama import init,Fore
from params import *
from data import *
from objetos import *
from concurrent.futures import ThreadPoolExecutor
from platform import system
from socket import gethostbyname
from logging import info,critical,warning


'este modulo contiene el script principal el cual llama a todos los modulos necesarios para su funcionamiento'

init()

def inicio_scan(msg):
    #solo se llama cuando son escaneos normales o selectivos 
    print(Fore.WHITE+f'\n\n#################################################')
    print(Fore.WHITE+msg)
    print('\n"esc" para salir\n')
    if param.timeout == None:
        lat_prom= latencia(param.ip)
        tim = timeout(lat_prom)
    else:
        tim = param.timeout
    print(f'timeout: {tim}')
    return tim


def crear_crawler(ip_):
    #solo se llama al realizar OSINT con shodan
    info('creando objeto crawler...')
    
    print(Fore.RED+'\niniciando crawler')
    
    #ip_num = ip numerica
    ip_num = ip.validacion(ip_)
    ip.informacion()
    ip.reputacion()

    #crawler
    crawler = Bot_Crawler(ip=ip_num)
    crawler.scrapping_shodan()
    crawler.obtener_links()


if param.hilo == None:
    hilo_= 100
else:
    hilo_ = param.hilo


try:
    #acciones de los parametros-----------------
    if param.shodan:
        try:
            if param.ip != None:
                if ',' in param.ip:
                    for x in param.ip.split(','):
                        crear_crawler(x)   
                else:       
                    crear_crawler(param.ip)
            else:
                print(Fore.RED+'especificar parametro [-ip]')
                
        except AttributeError:
            print(Fore.RED+'\nsin informacion al respecto\n')
            
        
    if param.agresivo:
        #t es el timeout para los escaneos agresivos
        if param.timeout == None:
            t = 0.5
        else:
            t = param.timeout

        
        
        if param.ip != None:
            print(Fore.WHITE+'''\n\n#################################################''')
            info('escaneo agresivo iniciado...')
            print(Fore.WHITE+'escaneo agresivo en curso...')
            json = cargar_json('data_puertos.json')
            print(f'num de hilos: {hilo_}\n\rtimeout:{t}')
            with ThreadPoolExecutor(max_workers=hilo_) as ejec:
                ip = gethostbyname(param.ip)
                for x in puertos:
                    
                    ejec.submit(scan_agresivo,ip,x,t,json)

            if not p_abiertos:
                print(Fore.RED+'\nningun puerto encontrado\n')        
                
            if param.info:
                for x in p_abiertos:
                    informacion(ip,x)
            
            preg_informe()
        
        else:
            print(Fore.RED+'\nespecificar parametro [-ip]\n')        
    
    
    #escaneo normal
    elif param.normal and param.buscar == None:
        if param.ip != None:
            
            scan= inicio_scan(msg='escaneo normal en curso...')

            threading.Thread(target=detener).start()
            scan_normal(param.ip,scan)   
            
        else:
            print(Fore.RED+'especificar parametro [-ip]') 

    #escaneo selectivo
    elif param.selectivo:
        if param.ip != None:
            
        
            scan= inicio_scan(msg='escaneo selectivo en curso...')

            scan_selectivo(param.ip,scan,param.selectivo)
            if param.info:
                for x in p_abiertos:
                    informacion(param.ip,x)

        else:
            print(Fore.RED+'\nespecificar parametro [-ip]\n')
    
    #para descubrir ips privadas
    elif param.ip != None and param.descubrir:
        
        
        if param.timeout != None:
            timeout_ = param.timeout
        else:
            timeout_ = 4
    
        print(Fore.GREEN+'rastreando ips privadas: ')
        for x in range(1,255):
            try:
            
                ejec= threading.Thread(target=descubrir_red,args=(param.ip,x,timeout_))
                if param.ip[-1] == 'x':
                    ejec.start()
                else:
                    print(Fore.RED+'la ip debe contener una x al final, ejemplo "192.168.0.x"')
                    break
                
            except: pass
            
        ejec.join()

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
                    print(Fore.CYAN+f'nombre de disp. en la red: {nombre}')
                    print(Fore.CYAN+f'direccion mac: {mac}')
                    print(Fore.CYAN+f'compania: {compania}')
                
        
        #buscar ips publicas
    elif param.buscar != None and not param.normal and param.ip == None:
    
        print(Fore.GREEN+'\n* rastreando ips publicas...\n')
        threading.Thread(target=detener).start()
    
        while n < param.buscar and not deten:
            
            busq = buscar()
            
            if busq != None:
                print(Fore.WHITE+busq)
                n+=1
            
        if not param.guardar:
            if str(input(Fore.WHITE+'[1] guardar informacion >> ')).strip() == '1':
                for ip in lista_ips:
                    agregar_arch(ip)
                print(Fore.GREEN+'\nla informacion fue guardada\n')
            else:
                print(Fore.RED+'\nla informacion no fue guardada\n')

    

    if param.ayuda:
        ayuda()

    if param.borrar:
        borrar_arch()

    elif param.abrir:
        abrir_arch(nombre_b)

    if param.lectura:
        abrir_arch(nombre_arch)     
except KeyboardInterrupt:
    deten = True
    exit(1)
except Exception as e: critical(f'error critico desconocido en el flujo principal')
finally:
    warning('la herramienta fue finalizada')