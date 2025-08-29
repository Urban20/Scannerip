'''este modulo contiene informacion de ciertas listas:
* lista usada para guardar puertos abiertos (p_abiertos)
* lista de ips publicas encontradas (lista_ips)'''

from threading import Lock
from colorama import Fore,init


init()



p_abiertos= [] # lista usada para guardar puertos abiertos

lista_ips = [] # lista de ips publicas encontradas

logo =Fore.RED+r'''
 
███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  ██ ██████      
██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ ██ ██   ██     
███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  ██ ██████      
     ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ ██ ██          
███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██ ██ ██
          
version 4.0                                                          
'''

