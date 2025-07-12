# Scip3 - Herramienta de Reconocimiento de Redes

<p align="center">
  <img src="https://github.com/Urban20/Scannerip/blob/main/img/logo.png?raw=true" alt="Logo del proyecto" width="600">
</p>


<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python&logoColor=white">
  <img alt="Shodan" src="https://img.shields.io/badge/Integración-Shodan-red?style=flat-square">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-Compatible-magenta?style=flat-square">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-Compatible-green?style=flat-square&logo=linux&logoColor=black">
  <img alt="Termux" src="https://img.shields.io/badge/Termux-Compatible-black?style=flat-square&logo=gnometerminal&logoColor=black">
  <img alt="Licencia" src="https://img.shields.io/badge/Licencia-MIT-yellow?style=flat-square">
</p>

> ⚠️ **ADVERTENCIA IMPORTANTE:**  
>  No me hago responsable del mal uso que se le pueda dar este software. Usar de forma ética

## Tabla de Contenidos
- [Características Principales](#características-principales)
- [Instalación Rápida](#instalación-rápida)
- [Modos de Operación](#modos-de-operación)
- [Uso Avanzado](#uso-avanzado)
- [Ejemplos Prácticos](#ejemplos-prácticos)
- [Capturas](#capturas)
- [Limitaciones](#limitaciones-actuales)
- [Apoyá el Proyecto](#apoyá-el-proyecto)


## Características Principales

### 🔍 Reconocimiento Avanzado
- Geolocalización precisa de IPs públicas
- Análisis de reputación (listas negras)
- Detección de servicios y dispositivos
- Extracción de metadatos de encabezados HTTP
- Soporte parcial para IPv6 en operaciones OSINT

### ⚡ Múltiples Estrategias de Escaneo
| Modo | Protocolo | Velocidad | Requisitos |
|------|-----------|-----------|------------|
| **Normal** | TCP | ⭐⭐ | Ninguno |
| **Agresivo** | TCP | ⭐⭐⭐⭐ | Multihilos |
| **Selectivo** | TCP | ⭐⭐⭐ | Puertos específicos |
| **SYN/ACK** | TCP | ⭐⭐⭐⭐ | Linux + Root |

### 🕸️ Integración con Shodan
- Detección de servicios expuestos
- Identificación de dispositivos IoT
- Extracción de URLs relacionadas
- Análisis de historial de escaneos

### 📊 Gestión de Resultados
- Generación de informes personalizados
- Guardado automático en formato TXT
- Sistema de logging configurable
- Visualización en tiempo real
- Filtrado avanzado de resultados

## Instalación Rápida

```bash
# Clonar repositorio
git clone https://github.com/Urban20/Scannerip.git
cd Scannerip

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar con ayuda
python scip3.py -h
```

## Modos de Operación

### 1. OSINT con Shodan (`-s`)
```bash
python scip3.py -ip target.com -s
```
- Geolocalización
- Reputación de IP
- Puertos históricos
- Servicios detectados
- URLs relacionadas

### 2. Escaneo Agresivo (`-a`)
```bash
python scip3.py -ip 192.168.1.1 -a -hl 200
```
- Multihilos (default: 100)
- Timeout configurable (`-t`)
- Fingerprinting automático (`-i`)

### 3. Escaneo SYN (`--syn`)
```bash
sudo python scip3.py -ip 10.0.0.1 --syn --no_filtrado
```
- Requiere root en Linux
- Modo sigiloso
- Detección de puertos filtrados
- Opción `--no_filtrado` para solo abiertos

### 4. Descubrimiento de Red (`-d`)
```bash
python scip3.py -ip 192.168.0.x -d
```
- Identificación de dispositivos locales
- Detección de fabricantes
- Obtención de nombres de host
- Análisis de TTL para identificar SO

## Uso Avanzado

### Parámetros Clave
| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `-m` | Escanear todos los puertos (1-65535) | `-a -m` |
| `-i` | Envío de payloads  | `-n -i` |
| `-g` | Guardar resultados | `-b 50 -g` |
| `-V6` | Forzar IPv6 en OSINT | `-s -V6` |
| `-r` | Reintentos (escaneos SYN) | `--syn -r 5` |
| `-hl` | Hilos paralelos | `-a -hl 200` |

### Gestión de Archivos
```bash
# Leer ips encontradas
python scip3.py --abrir

# Borrar historial
python scip3.py --borrar

# Generar informe personalizado
[Durante escaneo] > Ingresar título cuando se solicite
```

## Ejemplos Prácticos

**1. Auditoría completa de un objetivo:**
```bash
python scip3.py -ip example.com -s -a -i
```

**2. Escaneo sigiloso en red local:**
```bash
sudo python scip3.py -ip 192.168.1.105 --syn -t 0.2 --no_filtrado
```

**3. Descubrir dispositivos en la red:**
```bash
python scip3.py -ip 192.168.0.x -d
```

**4. Buscar 20 IPs públicas con puertos abiertos:**
```bash
python scip3.py -b 20 -g
```

## Capturas

### Panel de Ayuda (`-h`)
![Panel de Ayuda](https://github.com/Urban20/Scannerip/blob/main/img/parametros.png?raw=true)

### Escaneo con flag -n (escaneo normal)
![Shodan Integration](https://github.com/Urban20/Scannerip/blob/main/img/demo2.png?raw=true)

### Descubrimiento de direcciones ipv4 públicas
![Device Discovery](https://github.com/Urban20/Scannerip/blob/main/img/demo3.png?raw=true)


## Limitaciones Actuales
- ❌ Soporte limitado para IPv6
- ❌ Escaneos UDP no implementados
- ❌ Alto consumo de recursos en modo agresivo
- ❌ Requiere root para escaneos SYN

> ⚠️ **Nota sobre uso de APIs:**  
> El parámetro `-b` consume APIs con límites de solicitudes. Usar valores mayores a 50 puede causar bloqueos temporales.

## ⭐ Apoyá el Proyecto

Si te gusta mi proyecto, dale una estrellita

### Con esto me ayudas a:

- 📈 Aumentar la visibilidad del proyecto

- 🚀 Motivarme a seguir desarrollando mejoras

- 🔍 Permitir que más personas lo descubran
