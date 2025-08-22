# SCiP – Rama Experimental (Python + Go)

En esta rama se combina Python con Go para lograr escaneos agresivos ultrarrápidos.
La idea es simple: uso de Go para obtener paralelismo real entre escaneos y aprovechar su velocidad


## Características principales

Los escaneos agresivos (-a) ahora se ejecutan en Go mediante subprocess.

Go trabaja con 3.000 goroutines fijas, lo que permite una gran velocidad con menor consumo de recursos.

Parámetros como `-hl`, `-t` y `-M` no tienen efecto sobre los escaneos agresivos en esta variante.

Resultado: más rápido, más liviano, pero con un poco menos de estabilidad frente a la versión puramente en Python.

## Requisitos

Python 3.x

Go instalado (solo para compilar el binario una vez)

## Compilación del binario de Go

Debés compilar agresivo.go según tu sistema operativo y colocar el binario en la carpeta src/.

### Ejemplos:

```
# En Linux
go build -o agresivo src/agresivo.go

# En Windows
go build -o agresivo.exe src/agresivo.go
```

Una vez hecho esto, Python podrá comunicarse con el binario mediante subprocess.

## Uso

Ejecutá SCiP normalmente. Cuando uses el parámetro -a, se llamará al binario de Go en lugar de la versión Python.

> IMPORTANTE : Es posible que el antivirus muestre un falso positivo con el binario