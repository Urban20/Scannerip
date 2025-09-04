import socket
import logging
import data
from colorama import Fore


def scan_agresivo(ip,puerto,timeout,json_):
    
    'escaneos con muchos hilos (escaneos agresivos), mas rapidos, para protocolos TCP e ipv4 unicamente'
    try:   
        
        s = socket.socket()       
        s.settimeout(timeout)

        try:
            if s.connect_ex((ip.strip(),puerto)) == 0:
                print(Fore.GREEN+f'[*] puerto abierto >> {puerto}\n servicio mas probable: {json_.get(str(puerto))}\n\r')
                
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