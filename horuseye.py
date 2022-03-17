
# Manel Ferré
# Busqueda de vulnerabilidades en el sistema operativo
#    por fecha de hoy basado en vuls-control
#    por versión, busca si la versión instalada es vulnerable

from operator import truediv
import sys

from sys import exit
from os import remove
from os import path
import argparse
from tkinter.font import names



# Cargamos funciones segun su sistema operativo /win32/Linux/Darwin
sistemaOperativo = sys.platform
if(sistemaOperativo == "win32"):
    import fwindows
elif(sistemaOperativo == "linux"):
    import flinux
elif(sistemaOperativo == "darwin"):
    import fmac
# Funcion de busqueda de vulnerabilidades en CVE Details
import fvulns
# Configuración Constantes
import config 




# Variables globales
listTranslate=[] # Lista de sinónimos
listForzar=[]    # Lista de aplicaciones a monitorizar forzosas
listDemo=[]      # Lista de aplicaciones para DEMO (vulnerables)


# lee el fichero de translate para cambiar el nombre que nos dice el SO con el que tiene dado de alta CVDetails
def leeSinonimos():
    source = open(config.ConstFileSinonimos, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listTranslate.append(line)
    source.close()

# Aplicaciones a verificar aunque no las tengamos en el sistema
def leeAppFozar():
    source = open(config.ConstFileAppForzar, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listForzar.append(line)
    source.close()

# para demos, aplicaciones vulnerables
def leeAppDemoVulnerables():
    source = open(config.ConstDemoVulnerables, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listDemo.append(line)
    source.close()

# mueve las listas 
def ini():
    if(sistemaOperativo == "win32"):
        fwindows.listTranslate = listTranslate
    elif(sistemaOperativo == "Linux"):
        flinux.listTranslate = listTranslate
    elif(sistemaOperativo == "Darwin"):
        fmac.listTranslate = listTranslate


# crea los ficheros de aplicaciones
def createFile():
    if(sistemaOperativo == "win32"):
        fwindows.createFile()
    elif(sistemaOperativo == "Linux"):
        flinux.createFile()
    elif(sistemaOperativo == "Darwin"):
        fmac.createFile()

# Carga las demos
def vulnDemo():
    if len(listDemo)>0:
        for x in listDemo:
            nametemp = x.split(";") 
            fvulns.busca_cve(nametemp[0], nametemp[1])

# Busca segun version
def vulnVersion():
    if(sistemaOperativo == "win32"):
        fwindows.vulnVersion()
    elif(sistemaOperativo == "Linux"):
        flinux.vulnVersion()
    elif(sistemaOperativo == "Darwin"):
        fmac.vulnVersion()



def main():
    # argumentos
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', 
                    dest='create_file',
                    help='crea el fichero de aplicaciones encontradas')
    parser.add_argument('-m', action='store',
                    dest='monitorizar_apps',
                    help='monitoriza las apliaciones encontradas')
    parser.add_argument('-s', action='store',
                    dest='serach_vulns',
                    help='busca CVE segun version')
    parser.add_argument('-v', action='store',
                    dest='Verbose',
                    help='muestra información por pantalla')

   # namespace = parser.parse_args()





    if(sistemaOperativo == "win32"):
        print ("Sistema operativo Windows")
    elif(sistemaOperativo == "Linux"):
        print ("Sistema operativo Linux")
    elif(sistemaOperativo == "Darwin"):
        print ("Sistema operativo Mac")

    # borramos ficheros de apps y errores
    print ("Inicio de proceso")
    #if (namespace.monitorizar_apps):
    if path.exists(config.ConstFileAppInstaladas):        
        remove(config.ConstFileAppInstaladas)
    if path.exists(config.ConstFileAppNoEncontradas):        
        remove(config.ConstFileAppNoEncontradas)

    # leemos lista sinonimos
    print ("Lectura de sinónimos")
    if path.exists(config.ConstFileSinonimos):    
        leeSinonimos()    

    # leemos lista Aplicaciones a verificar si o si
    print ("Lectura de Aplicaciones forzadas")
    if path.exists(config.ConstFileAppForzar):    
        leeAppFozar()    

    # leemos lista Aplicaciones a verificar si o si
    print ("Lectura de Aplicaciones vulnerables (DEMO)")
    if path.exists(config.ConstDemoVulnerables):    
        leeAppDemoVulnerables()    

    # mueve listas
    ini()

    # creamos el fichero de applicaciones del servidor
    print ("Creamos ficheros temporales")
    createFile()

    # Buscamos vulnerabilidades a fecha de hoy
    # se basa en los ficheros generados y en el de forzado
    print ("Monitorizando aplicaciones")
    fvulns.monitorizarapps()

    # Buscamos vulnerabilidades segun version instalada
    print ("Buscando vulnerabilidades del software instalado, segun versión instalada")
    vulnVersion()

    print("buscamos las aplicaicones DEMO que son vulnerables")
    vulnDemo()

if __name__ == '__main__':
    main()