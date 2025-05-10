import socket
import ipaddress
from platform import system
from colorama import Fore,init
import requests
import func 
from bs4 import BeautifulSoup
import subprocess as sp
import re
import logging
import params

'este modulo contiene las clases que se utilizan en la herramienta'

init()


class Ip():
    'objeto ip que solo se utiliza con el crawler'
    def __init__(self):
        self.__ip = None
        self.validado = False
    
    def validacion(self,ip):
        'valida las ips para ver si efectivamente son correctas'
        logging.info('validando ip...')
        try:
        
            if params.param.V6:# se fuerza a la herramienta a traducir hosts en ipv6
                ipv6_num= socket.getaddrinfo(ip,None)[-1][-1][0].strip() 
                if ipaddress.IPv6Address(ipv6_num):
                    ip_num = ipv6_num
                else:
                    raise socket.gaierror    
            else:
                ip_num = socket.gethostbyname(ip) #fuerza la traduccion de dominios a ipv4

            if ipaddress.ip_address(ip_num).is_global:
                self.validado = True
                self.__ip = ip_num # atributo privado
                return ip_num
            else:
                print('\n[!] debe ser una ip global\n')
            
        except socket.gaierror:

            print(Fore.RED+'\n[!] el dominio/ip proporcionado tiene un formato incorrecto\n* para escanear ipv6, agregar argumento -V6')

        except Exception as e:
            logging.critical('ocurrio un error durante la validacion de ip')

    def informacion(self):
        'encargada de la obtencion de informacion de las ips a traves de las apis'

        logging.info('intentando obtener informacion de ip...')
        try:
            if self.validado and self.__ip != None:
                ip_api = requests.get(f'http://ip-api.com/json/{self.__ip}')
                shodan_api = requests.get(f'https://internetdb.shodan.io/{self.__ip}')
                geo = requests.get(f'http://www.geoplugin.net/json.gp?ip={self.__ip}')
                if shodan_api.status_code == 200:
                    print(Fore.GREEN+f'\nINFO:')
                    print(Fore.WHITE+f'''
#################################################                                                       
-ip: {shodan_api.json().get('ip')}
-puertos: {shodan_api.json().get('ports')}
-nombre de host: {shodan_api.json().get('hostnames')}
-tipo de dispositivo: {shodan_api.json().get('tags')}
#################################################''')
                if geo.status_code == 200 and ip_api.status_code == 200:
                    print(Fore.GREEN+f'\nGEOLOCALIZACION:')
                    print(Fore.WHITE+f'''
#################################################
-pais: {geo.json().get('geoplugin_countryName')}
-ciudad: {geo.json().get('geoplugin_city')}
-estado/prov: {geo.json().get('geoplugin_regionName')}
-ISP: {ip_api.json().get('isp')}
-org: {ip_api.json().get('org')}
#################################################''')

        except Exception as e:
            logging.critical('ocurrio un error al consumir las apis (metodo informacion, clase IP)')

    def reputacion(self):
        'metodo encargado de la reputacion de la ip'
        try:
            if self.validado:
                if not params.param.V6:
                    logging.info('intentando obtener reputacion de ip...')
                    rep = func.confiabilidad_ip(self.__ip)
                    if rep != None:
                        match rep:
                            case 'failure-message':
                                print(Fore.RED+'en la lista negra')
                            case 'no valida':
                                print(Fore.YELLOW+'no se puede obtener la reputacion')
                            case 'success-message':
                                print(Fore.CYAN+'fuera de la lista negra')
            else:
                print(Fore.RED+'\n[!] no se pudo obtener la reputacion: ip no validada\n')
        except Exception as e:
            logging.critical('hubo un error durante la obtencion de reputacion de la ip')

ip = Ip()

class Bot_Crawler():
    '''un crawler es un bot que rastrea informacion de un sitio web, esto se encarga de:
    * webscraping
    * revisar la accesibilidad de las urls expuestas de las ips osinteadas'''
    
    def __init__(self,ip):
        self.ip = ip
        self.html = BeautifulSoup(requests.get(f'https://www.shodan.io/host/{self.ip}').text,'html.parser')
        self.contenido = self.html.get_text().strip()
        self.status = requests.get(f'https://www.shodan.io/host/{self.ip}').status_code



    def scrapping_shodan(self):
        'metodo encargado de la obtencion de informacion en shodan (scraping web)'
        logging.info('se intenta hacer scraping en shodan...')

        if  self.status == 200 and ip.validado and self.ip != None:
            print(Fore.RED+'\n###########\nshodan\n###########\n')
            
            ult_escan = re.search(r'\d+-\d+-\d+',self.contenido.lower())
            protocolos = re.findall(r'\d+ /\n(\D+)',self.contenido)
            puertos = re.findall(r'(\d+) /\n\D+',self.contenido)
            contenido = self.html.find_all('div',class_='card card-padding banner')
            #fechas de cada escaneo por separado
            fechas= re.findall(r' \| (\d+-\d+-\d+)t',self.contenido.lower())

            print(Fore.WHITE+f'\033[1;32multima fecha registrada: \033[1;37m{ult_escan.group()}')

            for proto,puert,cont,fech in zip(protocolos,puertos,contenido,fechas):
                print(f'\n#################################################')
                print(Fore.GREEN+f'\nfecha del puerto escaneado: \033[1;37m{fech}\n')   
                print(Fore.WHITE+f'\033[1;32mprotocolo: \033[1;37m{proto.strip()} \033[1;32mpuerto: \033[1;37m{puert.strip()}\n')
                lim_caracteres = 650

                if re.search(r'camera|camara|webcam|hikvision|dahua|rtsp',cont.get_text().strip().lower()):
                    info = '[+] posible camara IP detectada\n'

                elif re.search('ftp',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > lim_caracteres:
                    info = '[+] posible protocolo FTP detectado\n'

                elif re.search('smtp',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > lim_caracteres:
                    info = '[+] posible protocolo SMTP detectado (protocolo simple de transferencia de correo)\n'

                elif re.search('ssh',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > lim_caracteres:
                    info = '[+] posible servicio ssh detectado\n'
                
                elif re.search('html',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > lim_caracteres:
                    info = '[+] posible pagina web detectada\n'
                else:
                    info = cont.get_text().strip()

                print(Fore.WHITE+f'\rservicio en escucha\r\n\r\n{info}\r\n#################################################\r\n')
            
               
    def obtener_links(self):
        'obtiene los links que expone shodan de las ips'
        logging.info('se inicia la obtencion de enlaces...')
        status = func.cargar_json('status.json')
        if ip.validado and self.status == 200:
            try:
                links = re.findall(r'https?://\d+.\d+.\d+.\d+:\d+',str(self.html))
                if links:
                    print(Fore.GREEN+'''URLS RELACIONADAS:
                          ''')
                    for link in links:
                        print(Fore.WHITE+link)
                        print(func.rastreo(link,status))
            
            except Exception as e:
                logging.critical('ocurrio un error en obtener_links')

class Ipv4():
    'esta clase se encarga de las ipv4 PRIVADAS unicamente'
    def __init__(self,ip):
        self.ipv4 = ip

        # atributos privados de la clase
        self.__nombre = None
        self.__mac = None
        self.__compania = None

    def ttl(self):
        'metodo que intenta obtener el ttl de una ipv4 privada '
        logging.info('calculando ttl...')
        try:
            out= sp.check_output(['ping','-c','1',self.ipv4],text=True)
            return re.search(r'ttl=(\d+)',out.lower()).group(1)
        except:
            return None

    def obtener_mac(self):
        'metodo que intenta obtener las direcciones MAC de las ipv4 privadas'

        logging.info('obteniendo direcciones mac...')
        try:
            out =str(sp.check_output(['ip','neigh','show',self.ipv4],text=True))
            
            self.__mac = re.search(r'\w+:\w+:\w+:\w+:\w+:\w+',out.lower()).group()

            return self.__mac
        except:
            return None
    def obtener_nombre(self):
        'metodo que intenta obtener el nombre del dispositivo de la red'
        logging.info('obteniendo nombres...')
        try:
            self.__nombre = re.search(r'(\w+)\.',socket.gethostbyaddr(self.ipv4)[0].lower()).group(1).strip()
        except:
            self.__nombre = '[desconocido]'
        return self.__nombre
    
    def obtener_compania(self):
        'metodo que intenta obtener la compania fabricante del producto'
        logging.info('obteniendo informacion de las companias de los dispositivos...')
        try:
            api= requests.get(f'https://www.macvendorlookup.com/api/v2/{self.__mac}').json()
            for el in api:
                self.__compania = str(el['company'])
                return self.__compania
        except:
            return None
        