import logging
import json
from colorama import Fore
import sys


try:
    with open('opciones.json','r') as opciones:
        cont_op = json.load(opciones)
except:
    print(Fore.RED+'\ncofiguracion incorrecta, revisar opciones.json\n')
    sys.exit(1) 

op = cont_op['nivel']

match op:
    case 'basico':
        nivel = logging.WARNING
    case 'detallado':
        nivel = logging.INFO
    case _:
        print(Fore.RED+'\ncofiguracion incorrecta, revisar opciones.json\n')
        sys.exit(1)


#nombre del archivo donde se guardan las ips encontradas
nombre_b= cont_op['arch-ips-encontradas']


#nombre del archivo que se crea al guardar una ip escaneada
nombre_arch = cont_op['arch-guardado-de-puertos']

#la funcion para agregar arhivos, corresponde a buscar
def agregar_arch(datos):
    with open(nombre_b,'a') as ip_lista:
        ip_lista.write(datos)

def abrir_arch(txt):
    'inicia la lectura de archivos .txt'
    logging.info('iniciando lectura de archivo...')
    try:
        with open(txt,'r') as arch:
            print(arch.read())
        
    except FileNotFoundError:
        logging.error('no se pudo encontrar el archivo')
    except Exception as e:
        logging.critical(f'hubo un error en la apertura de un archivo')

def cargar_json(archivo):
    'funcion utilizada para la lectura de archivos .json'
    try:
        logging.info('cargando json...')
        with open(f'json/{archivo}','r') as arch:
            #retorna el diccionario
            return json.load(arch)
    except Exception as e:
        logging.critical(f'error en la carga de uno o varios archivos JSON')

def crear_informe(ip,puerto,titulo):
    'crea los informes que van a ser guardados en los txt'
    logging.info('creando informe...')
    try:
        informe=f'''
##############################
titulo : {titulo}
ip / dominio: {ip}

puertos encontrados:
{puerto}
##############################
        '''


        with open(nombre_arch,'a') as arch:
            arch.write(informe)
    except Exception as e:
        logging.critical('ocurrio un error en la creacion del informe')


def borrar_arch():
    'una pequeña funcion para borrar contenido de archivos'
    try:
        with open(nombre_b,'w') as arch:
            arch.write('')
        print(Fore.GREEN+f'\n[*] archivo borrado: {nombre_b}\n')
        logging.info('se elimino el contenido del registro de ips encontradas')
    except:
        logging.error('hubo un error en borrar_arch')