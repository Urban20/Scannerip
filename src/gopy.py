import subprocess
import params
import platform
import os
import sys

if platform.system() == 'Windows':
    BINARIO = 'agresivo.exe'
elif platform.system() == 'Linux': 
    BINARIO = './agresivo'


TEMP = 'temp.temp'

def leer_puertos_go():
    try:
        with open(TEMP,'r') as temp:
            for linea in temp:
                yield linea.strip()
            
    except FileNotFoundError:
        print(f'no se encuentra el archivo temporal {TEMP}')

    finally: os.remove(TEMP)

def go_agresivo(ip : str):
    try:
        comando = subprocess.run([BINARIO,ip])
        if comando.returncode == 0 and params.param.info:
            leer_puertos_go()
    except FileNotFoundError:
        print('\nse debe disponer del binario para escaneos agresivos (.exe o binario de Linux segun corresponda)\n')
        sys.exit(1)