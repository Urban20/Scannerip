import socket
import ipaddress
from platform import system
from colorama import Fore,init
import requests
import func 
from bs4 import BeautifulSoup
from subprocess import run
import re
import logging

'este modulo contiene las clases que se utilizan en el script'

init()

#objeto ip que solo se utiliza con el crawler
class Ip():
    def __init__(self):
        self.ip = None
        self.validado = False
    
    def validacion(self,ip):
        logging.info('validando ip...')
        try:
            ip_ =socket.gethostbyname(ip)
            if ipaddress.ip_address(ip_).is_global:
                self.validado = True
                self.ip = ip_
                return ip_
            else:
                print('debe ser una ip global')
            
        except socket.gaierror:

            print(Fore.RED+'el dominio/ip proporcionado es incorrecto')

        except Exception as e:
            logging.critical('ocurrio un error durante la validacion de ip')

    def informacion(self):
        logging.info('intentando obtener informacion de ip...')
        try:
            if self.validado and self.ip != None:
                ip_api = requests.get(f'http://ip-api.com/json/{self.ip}')
                shodan_api = requests.get(f'https://internetdb.shodan.io/{self.ip}')
                geo = requests.get(f'http://www.geoplugin.net/json.gp?ip={self.ip}')
                if shodan_api.status_code == 200:
                    print(Fore.GREEN+f'\nINFO:')
                    print(Fore.WHITE+f'''
#################################################                                                       
-ip:{shodan_api.json().get('ip')}
-puertos: {shodan_api.json().get('ports')}
-nombre de host:{shodan_api.json().get('hostnames')}
-tipo de dispositivo:{shodan_api.json().get('tags')}
#################################################''')
                if geo.status_code == 200 and ip_api.status_code == 200:
                    print(Fore.GREEN+f'\nGEOLOCALIZACION:')
                    print(Fore.WHITE+f'''
#################################################
-pais:{geo.json().get('geoplugin_countryName')}
-ciudad:{geo.json().get('geoplugin_city')}
-estado/prov:{geo.json().get('geoplugin_regionName')}
-ISP:{ip_api.json().get('isp')}
-org:{ip_api.json().get('org')}
#################################################''')

        except Exception as e:
            logging.critical('ocurrio un error al consumir las apis apis')

    def reputacion(self):
        logging.info('intentando obtener reputacion de ip...')
        try:
            if self.validado:
                rep = func.confiabilidad_ip(self.ip)
                if rep != None:
                    match rep:
                        case 'failure-message':
                            print(Fore.RED+'en la lista negra')
                        case 'no valida':
                            print(Fore.YELLOW+'no se puede obtener la reputacion')
                        case 'success-message':
                            print(Fore.CYAN+'fuera de la lista negra')
            else:
                print(Fore.RED+'no se pudo obtener la reputacion: ip no validada')
        except Exception as e:
            logging.critical('hubo un error durante la obtencion de reputacion de la ip')

ip = Ip()

class Bot_Crawler():

    def __init__(self,ip):
        self.ip = ip
        self.html = BeautifulSoup(requests.get(f'https://www.shodan.io/host/{self.ip}').text,'html.parser')
        self.contenido = self.html.get_text().strip()
        self.status = requests.get(f'https://www.shodan.io/host/{self.ip}').status_code



    def scrapping_shodan(self):
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
                if re.search('html',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > 650:
                    info = 'posible pagina web'
                elif re.search('ssh',cont.get_text().strip().lower()) and len(cont.get_text().strip()) > 650:
                    info = 'posible servicio ssh'
                else:
                    info = cont.get_text().strip()

                print(Fore.WHITE+f'\rservicio en escucha\r\n\r\n{info}\r\n#################################################\r\n')
            
               
    def obtener_links(self):
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
    def __init__(self,ip):
        self.ipv4 = ip
        self.nombre = None
        self.mac = None
        self.compania = None

    def ttl(self):
        logging.info('calculando ttl...')
        out= str(run(args=['ping','-c','1',self.ipv4],capture_output=True,text=True)).split()
        for x in out:
            if 'ttl' in x:
                return int(x.split('=')[-1].strip())

    def obtener_mac(self):
        logging.info('obteniendo direcciones mac...')
        for el in str(run(['ip','neigh','show',self.ipv4],text=True,capture_output=True)).split():
            if ':' in el:
                self.mac = el

        return self.mac
            
    def obtener_nombre(self):
        logging.info('obteniendo nombres...')
        try:
            self.nombre = socket.gethostbyaddr(self.ipv4)[0].split('.')[0].strip()
        except:
            self.nombre = '[desconocido]'
        return(self.nombre)
    
    def obtener_compania(self):
        logging.info('obteniendo informacion de las companias de los dispositivos...')
        try:
            api= requests.get(f'https://www.macvendorlookup.com/api/v2/{self.mac}').json()
            for el in api:
                self.compania = str(el['company'])
                return self.compania

        except:
            return None