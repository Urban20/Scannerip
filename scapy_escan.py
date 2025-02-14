from scapy.all import *
import re
from colorama import init,Fore
import logging
from params import *

init()


# agregar escaneos udp
# revisar los reintentos
#intentar ajustar el tiempo

if param.reintento != None:
    reintento = param.reintento
else:
    reintento = 3


def escaneo_ack(ip,puerto,timeout_):
    conf.verb = 0
    s_ack = sr1(IP(dst=ip)/TCP(dport=puerto,flags='A'),timeout=timeout_,retry=reintento)#type: ignore
    
    if s_ack == None:
        print(Fore.YELLOW+f'\n[*] puerto filtrado (paquete descartado silenciosamente) >> {puerto}\n')
    elif re.search('ICMP',str(s_ack)):
        print(Fore.YELLOW+f'\n[*] puerto filtrado (ICMP recibido) >> {puerto}\n')
    
def escaneo_syn(ip,puerto,timeout):
    #s_syn --> escaneo syn --> variable
    try:
        
        conf.verb = 0
        s_syn =  sr1(IP(dst=ip)/TCP(dport=puerto,flags='S'),timeout=timeout,retry=reintento)#type: ignore
        if s_syn != None :
            if re.search('SA',str(s_syn)):
                print(Fore.GREEN+f'\n[*] puerto abierto >> {puerto}\n')
        else:
            escaneo_ack(ip=ip,puerto=puerto,timeout_=timeout)

    except AttributeError:
        pass
    except:
        logging.error('error en escaneo syn')
    
