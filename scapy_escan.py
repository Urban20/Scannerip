'''modulo donde esta el codigo responsable de manejar escaneos con scapy:
* maneja los escaneos de syn y ack disponibles en linux '''

from scapy.all import *
import re
from colorama import init,Fore
import logging
from params import *
from data import p_abiertos

init()



if param.reintento != None:
    reintento = param.reintento
else:
    reintento = 3


def escaneo_ack(ip,puerto,timeout_):
    #s_ack --> hace refencia a los escaneos ack --> variable
    conf.verb = 0
    s_ack = sr1(IP(dst=ip)/TCP(dport=puerto,flags='A'),timeout=timeout_,retry=reintento)#type: ignore
    
    if s_ack == None:
        print(Fore.YELLOW+f'\n[*] puerto filtrado (paquete descartado silenciosamente) >> {puerto}\n')
    elif re.search('ICMP',str(s_ack)):
        print(Fore.YELLOW+f'\n[*] puerto filtrado (ICMP recibido) >> {puerto}\n')
    
def escaneo_syn(ip,puerto,timeout):
    #s_syn --> hace referencia a los escaneo syn --> variable
    try:
        
        conf.verb = 0
        s_syn =  sr1(IP(dst=ip)/TCP(dport=puerto,flags='S'),timeout=timeout,retry=reintento)#type: ignore
        if s_syn != None :
            if re.search('SA',str(s_syn)):
                print(Fore.GREEN+f'\n[*] puerto abierto >> {puerto}\n')
                if param.info:
                    p_abiertos.append(puerto)
                
        else:
            if not param.no_filtrado:
                escaneo_ack(ip=ip,puerto=puerto,timeout_=timeout)

    except AttributeError:
        pass
    except:
        logging.error('error en escaneo syn')
    
