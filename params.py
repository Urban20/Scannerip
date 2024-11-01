import argparse


args = argparse.ArgumentParser(description='scip3 es una herramienta de reconocimiento de redes desarrollada por Urb@n con busqueda en shodan y escaneo de redes, entre otras cosas',
usage='escribir el parametro -h o --ayuda para ver las funciones disponibles',add_help=False)

args.add_argument('-s','--shodan',action=argparse.BooleanOptionalAction)
args.add_argument('-n','--normal',action=argparse.BooleanOptionalAction)
args.add_argument('-a','--agresivo',action=argparse.BooleanOptionalAction)
args.add_argument('-p','--selectivo',type=str)
args.add_argument('-ip','--ip',type=str)
args.add_argument('-b','--buscar',type=int)
args.add_argument('-g','--guardar',action=argparse.BooleanOptionalAction)
args.add_argument('-i','--info',action=argparse.BooleanOptionalAction)
args.add_argument('-h','--ayuda',action=argparse.BooleanOptionalAction)
args.add_argument('-l','--lectura',action=argparse.BooleanOptionalAction)
args.add_argument('-t','--timeout',type=float)
args.add_argument('-m','--masivo',action=argparse.BooleanOptionalAction)
args.add_argument('-cls','--borrar',action=argparse.BooleanOptionalAction)
args.add_argument('-abrir','--abrir',action=argparse.BooleanOptionalAction)
param = args.parse_args()