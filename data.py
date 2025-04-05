from threading import Lock
from colorama import Fore,init

'este modulo contiene algunas de las variables que se utilizan en el script'
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

