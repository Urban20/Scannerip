from threading import Lock
import params
from colorama import Fore

status = {
    100: "Continue: El servidor ha recibido los encabezados de la solicitud y el cliente puede continuar enviando el cuerpo de la solicitud.",
    101: "Switching Protocols: El servidor acepta cambiar el protocolo de comunicación (como de HTTP a WebSocket).",
    102: "Processing: El servidor ha recibido la solicitud, pero aún no ha terminado de procesarla (utilizado en WebDAV).",
    200: "OK: La solicitud ha sido procesada con éxito y el servidor devuelve los datos solicitados.",
    201: "Created: La solicitud ha tenido éxito y ha resultado en la creación de un recurso.",
    202: "Accepted: La solicitud ha sido aceptada, pero aún no se ha completado el procesamiento.",
    203: "Non-Authoritative Information: La respuesta contiene información no verificada proveniente de un tercero.",
    204: "No Content: La solicitud ha tenido éxito, pero el servidor no devuelve ningún contenido.",
    205: "Reset Content: Similar a 204, pero indica al cliente que debe reiniciar la vista o formulario.",
    206: "Partial Content: El servidor devuelve parte del contenido solicitado, generalmente en respuesta a solicitudes de rango.",
    300: "Multiple Choices: Hay varias opciones para el recurso solicitado y el cliente debe elegir una.",
    301: "Moved Permanently: El recurso solicitado ha sido movido de manera permanente a una nueva URL.",
    302: "Found: El recurso ha sido movido temporalmente a otra URL (usualmente se utiliza para redirecciones).",
    303: "See Other: El servidor sugiere al cliente una nueva URL para obtener el recurso usando el método GET.",
    304: "Not Modified: El recurso no ha cambiado desde la última solicitud, por lo que el cliente puede usar una versión en caché.",
    305: "Use Proxy: El recurso solicitado solo está disponible a través de un proxy.",
    307: "Temporary Redirect: Similar a 302, pero el método de la solicitud no debe cambiar (se debe usar el método original).",
    308: "Permanent Redirect: Similar a 301, pero garantiza que el método no cambie (usado en redirecciones permanentes).",
    400: "Bad Request: La solicitud contiene sintaxis incorrecta o no puede ser procesada por el servidor.",
    401: "Unauthorized: La solicitud requiere autenticación. El cliente debe autenticarse para obtener la respuesta.",
    402: "Payment Required: Este código es reservado para usos futuros (originalmente pensado para sistemas de pago).",
    403: "Forbidden: El cliente no tiene permiso para acceder al recurso solicitado, incluso si ha sido autenticado.",
    404: "Not Found: El recurso solicitado no ha sido encontrado en el servidor.",
    405: "Method Not Allowed: El método HTTP utilizado no está permitido para el recurso solicitado.",
    406: "Not Acceptable: El recurso no está disponible en el formato solicitado.",
    407: "Proxy Authentication Required: Similar a 401, pero requiere autenticación a través de un proxy.",
    408: "Request Timeout: El servidor agotó el tiempo de espera antes de recibir la solicitud completa.",
    409: "Conflict: Hay un conflicto con el estado actual del recurso (usualmente relacionado con solicitudes PUT).",
    410: "Gone: El recurso solicitado ya no está disponible y no se espera que vuelva a estarlo.",
    411: "Length Required: El servidor requiere que la solicitud incluya el encabezado Content-Length.",
    412: "Precondition Failed: Una condición en los encabezados de la solicitud no ha sido cumplida por el servidor.",
    413: "Payload Too Large: El servidor rechaza la solicitud porque el cuerpo es demasiado grande.",
    414: "URI Too Long: La URI solicitada es demasiado larga para ser procesada por el servidor.",
    415: "Unsupported Media Type: El servidor no puede manejar el tipo de medio solicitado en la solicitud.",
    416: "Range Not Satisfiable: El cliente ha solicitado una porción de un archivo que el servidor no puede proporcionar (usualmente en solicitudes de rango).",
    417: "Expectation Failed: El servidor no puede cumplir con los requisitos del encabezado Expect de la solicitud.",
    500: "Internal Server Error: El servidor encontró una condición inesperada que le impidió completar la solicitud.",
    501: "Not Implemented: El servidor no tiene soporte para la funcionalidad requerida para procesar la solicitud.",
    502: "Bad Gateway: El servidor recibió una respuesta inválida de un servidor upstream mientras actuaba como gateway o proxy.",
    503: "Service Unavailable: El servidor no está disponible, generalmente debido a sobrecarga o mantenimiento.",
    504: "Gateway Timeout: El servidor acting como gateway no recibió una respuesta a tiempo de un servidor upstream.",
    505: "HTTP Version Not Supported: El servidor no soporta la versión del protocolo HTTP utilizada en la solicitud."
}

#puertos utilizados comunmente

if params.param.masivo:
    
    puertos = list(range(1,65535))

else:
    
    puertos = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 
    85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
    254, 255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481,
    497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648,
    666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880,
    888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1007, 1009, 1010, 1011, 1021, 
    1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
    1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081,
    1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102,
    1104, 1105, 1106, 1107, 1108, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154,
    1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233,
    1234, 1236, 1244, 1247, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417,
    1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666,
    1687, 1688, 1700, 1717, 1718, 1720, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
    1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,2000, 2001,2002,2003,2004,2005,2006,2007,2008,2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065,
    2068,2082,2083,2099,2100,2103,2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
    2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
    2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2920, 2967, 2998,
    3000, 3001, 3003, 3005, 3006, 3011, 3013, 3017, 3030, 3050, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3268, 3283,
    3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517,
    3527, 3546, 3551, 3580, 3659, 3689, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4045, 4111,
    4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
    5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5120, 5190, 5200,
    5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,5432, 5440, 5500, 5544, 5550, 5555, 5560, 5566, 5631,
    5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901,
    5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998,
    5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,6379,
    6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789,
    6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435,
    7443, 7496, 7512, 7547, 7624, 7627, 7676, 7741, 7777, 7778, 7800, 7801, 7900, 7901, 7902, 7903, 7911, 7920, 7921, 7937, 7938,
    7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
    8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8880, 8883, 8888, 8899, 8994, 9000,
    9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200,
    9207, 9220, 9290, 9415, 9418, 9443, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9943,
    9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722,
    13724, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
    16018, 17988, 18040, 18181, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800,
    25793, 25826, 25900, 25901, 27444, 27500, 27715, 28201, 30000, 30718, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
    32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572,
    34573, 35500, 38292, 40193, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
    51494, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443,
    61532, 61900, 62078, 63331, 65129, 65389
    ]

descripciones = {
    20: 'Transferencia de datos.',
    21: 'transferencia de archivos.',
    22: 'SSH (Secure Shell)',
    23: 'Telnet ',
    25: 'SMTP – Envío de correos electrónicos.',
    53: 'Resolución de nombres de dominio.',
    67: 'Asignación de direcciones IP en redes.',
    68: 'asignación de direcciones IP.',
    69: 'Transferencia de archivos simple.',
    80: 'Navegación web sin cifrar.',
    110: 'Recepción de correos electrónicos.',
    115: 'Transferencia simple de archivos (obsoleto).',
    135: 'Comunicación entre procesos en redes Windows.',
    137: 'Uso en redes locales de Windows para compartir archivos.',
    138: 'NetBIOS Datagram Service.',
    139: 'Uso en redes locales de Windows para compartir archivos.',
    143: 'Recepción de correos con acceso remoto a buzón.',
    161: 'Administración de red.',
    162: 'Notificaciones de SNMP.',
    443: 'HTTPS - Navegación web cifrada.',
    445: 'compartición de archivos en Windows.',
    465: 'Envío de correos electrónicos cifrados.',
    514: 'Envío de logs de sistema a servidores remotos.',
    587: 'Envío de correos electrónicos cifrados con seguridad adicional.',
    631: 'Protocolo de impresión en red.',
    993: 'IMAPS (IMAP over SSL) – IMAP cifrado.',
    995: 'POP3S (POP3 over SSL) – POP3 cifrado.',
    3306: 'MySQL – Conexión a bases de datos MySQL.',
    3389: 'Acceso remoto a escritorio de Windows.',
    5432: 'Conexión a bases de datos PostgreSQL.',
    5900: 'Acceso remoto a escritorios.',
    6379: 'Redis – Base de datos en memoria',
    1194: 'OpenVPN – Servicio de VPN seguro.',
    1433: 'Base de datos SQL de Microsoft.',
    1434: 'Monitoreo de SQL Server.',
    1521: 'Oracle DB – Conexión a bases de datos Oracle.',
    1723: 'VPN menos segura.',
    2049: 'compartición de archivos',
    2082: 'Acceso al panel de control web cPanel.',
    2083: 'cPanel con cifrado SSL.',
    8080: 'HTTP alternativo',
    8443: 'HTTPS alternativo',
    8888: 'HTTP alternativo',
    7547: 'Gestión remota de dispositivos',
    119: 'Transferencia de artículos de noticias Usenet.',
    515: 'Servicio de impresión en red.',
    6667: 'Comunicación en tiempo real mediante chat.'
}

cerradura = Lock()

#nombre del archivo que se crea al ingresar 1 en los escaneos
nombre_arch = 'scannerip.txt'

#nombre del archivo perteneciente a el parametro -b
nombre_b='ips_encontradas.txt'
p_abiertos= []

descrip = []

elementos=[]

logo =Fore.RED+r'''
    
┌────────────────────────────────────────────────────────────────────────────┐
│ ________  ________  ________  ________   ________   _______   ________     │
│|\   ____\|\   ____\|\   __  \|\   ___  \|\   ___  \|\  ___ \ |\   __  \    │
│\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \|\  \   │
│ \ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \   _  _\  │
│  \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \\  \| │
│    ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \__\\ \__\ \_______\ \__\\ _\ │
│   |\_________\|_______|\|__|\|__|\|__| \|__|\|__| \|__|\|_______|\|__|\|__|│
│   \|_________|                                                             │
│                                                                            │
│                                                                            │
│              ___  ________                                                 │
│             |\  \|\   __  \                                                │
│ ____________\ \  \ \  \|\  \                                               │
│|\____________\ \  \ \   ____\                                              │
│\|____________|\ \  \ \  \___|                                              │
│                \ \__\ \__\                                                 │
│                 \|__|\|__|                                                 │
└────────────────────────────────────────────────────────────────────────────┘
    Version 3.0   
    
    '''
autor =Fore.GREEN+'''
propiedad de:

██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ██╗
██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██║   ██║██████╔╝██████╔╝██║██╗██║██╔██╗ ██║
██║   ██║██╔══██╗██╔══██╗██║██║██║██║╚██╗██║
╚██████╔╝██║  ██║██████╔╝╚█║████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚╝╚═══╝ ╚═╝  ╚═══╝                                      
'''