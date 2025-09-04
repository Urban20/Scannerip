import params
import requests
import logging
import socket

def fingerprint(ip,puerto): # NO llamar fingerprint directamente, en su lugar se llama a informacion del modulo func
    'intenta obtener informacion de puertos abiertos a traves de payloads especificos'
    logging.info('iniciando fingerprint...')
    buffer = 1024
    msg = None
    dic = None
    for x in ['https','http']:
        
        try: 
            dic=dict(requests.get(f'{x}://{ip}:{str(puerto)}',timeout=5).headers)
            break
        except:
            dic = None
            continue
        
    if dic == None:
        try:
            
            
            if params.param.timeout == None:# se gestiona el timeout para el envio de payloads
                t_payload = 1
            else:
                t_payload = params.param.timeout

            for x in [b'\x00',b'\x90' * 16,b'Help\n',b'\x00\xff\x00\xff',
                    b'USER anonymous\r\n',b'\x10\x20\x30\x40',b'test',b'test\r\n'
                    , b'\x01\x02\x03', b'GET / HTTP/1.1\r\n\r\n',
                    b'\xff\xff\xff\xff']:
                try:
                    c_payload = socket.socket()
                    c_payload.settimeout(t_payload)
                    if c_payload.connect_ex((ip,puerto)) == 0:
                        c_payload.send(x)

                        msg = c_payload.recv(buffer)
                        if msg == b'':
                            raise Exception
                        if msg != None:  
                            return msg.decode()
                    
                except TimeoutError: msg = None
                
                except UnicodeDecodeError:
                    return str(msg)

                except Exception as e:
                    logging.info(f'hubo un problema al enviar un payload: {e} ')
                    continue
                finally : c_payload.close()


               
                
      
        except UnicodeDecodeError: return str(msg)

        
    else:
        try:
            encabezado = ''
            for x in dic:
                encabezado += f'{x}: {dic[x]}\n\r'
            return encabezado
        except:
            return None
    logging.info('se finalizo el fingerprint')
