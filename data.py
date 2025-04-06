from threading import Lock
from colorama import Fore,init

'este modulo contiene informacion de ciertas listas'

init()
cerradura = Lock()


p_abiertos= []

descrip = []

lista_ips = []

logo =Fore.RED+r'''
 
███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  ██ ██████      
██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ ██ ██   ██     
███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  ██ ██████      
     ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ ██ ██          
███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██ ██ ██
          
version 4.0                                                          
'''

