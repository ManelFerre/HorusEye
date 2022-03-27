
# Manel Ferré
# Busqueda de vulnerabilidades en el sistema operativo
#    por fecha de hoy basado en vuls-control
#    por versión, busca si la versión instalada es vulnerable

#from operator import truediv
import sys

#from sys import exit
from os import remove
from os import path
import argparse


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

def gestionargumentos():


    appdesc = "HorusEye Buscador de vuberabilidades CVEs de programas instalados."
    parser = argparse.ArgumentParser(description=appdesc)
    # argumentos
    parser.add_argument('-c', 
                        dest='create_file',
                        action='store_true', 
                        default='False',
                        required=False,
                        help='Crea fichero temporal.')
    parser.add_argument('-m', 
                        dest='monitorizar_apps',
                        action='store_true', 
                        default='False', 
                        required=False,
                        help='Monitoriza el sistema.')
    parser.add_argument('-s', 
                        dest='search_vulns',
                        action='store_true', 
                        default='False', 
                        required=False,
                        help='Busca vulnerabilidades por versión.')
    parser.add_argument('-v', 
                        dest='verbose',
                        action='store_true', 
                        default='False', 
                        required=False,
                        help='Muestra información por pantalla')
    parser.add_argument('-d', 
                        dest='demo',
                        action='store_true', 
                        default='False', 
                        required=False,
                        help='Ejecuta la demo')

    return parser.parse_args()

def print_log(_verb, Text):
   if (_verb == True): 
       print(Text)

def main():
    namespace = gestionargumentos()
    _verbose = namespace.verbose

    if(sistemaOperativo == "win32"):
        print_log (_verbose, "Sistema operativo Windows")
    elif(sistemaOperativo == "Linux"):
        print_log (_verbose, "Sistema operativo Linux")
    elif(sistemaOperativo == "Darwin"):
        print_log (_verbose, "Sistema operativo Mac")

    print_log (_verbose, "Inicio de proceso")

    # borramos ficheros de apps y errores
    if (namespace.create_file is True):
        if path.exists(config.ConstFileAppInstaladas):        
            remove(config.ConstFileAppInstaladas)
        if path.exists(config.ConstFileAppNoEncontradas):        
            remove(config.ConstFileAppNoEncontradas)

    # leemos lista sinonimos
    if path.exists(config.ConstFileSinonimos):    
        print_log (_verbose, "Lectura de sinónimos")
        leeSinonimos()    

    # leemos lista Aplicaciones a verificar si o si
    if path.exists(config.ConstFileAppForzar):    
        print_log (_verbose, "Lectura de Aplicaciones forzadas")
        leeAppFozar()    

    # leemos lista Aplicaciones a verificar si o si
    if path.exists(config.ConstDemoVulnerables):    
        print_log (_verbose, "Lectura de Aplicaciones vulnerables (DEMO)")
        leeAppDemoVulnerables()    

    # mueve listas
    ini()

    # creamos el fichero de applicaciones del servidor
    if (namespace.create_file is True):
        print_log (_verbose, "Creamos ficheros temporales")
        createFile()

    # Buscamos vulnerabilidades a fecha de hoy
    # se basa en los ficheros generados y en el de forzado
    if (namespace.monitorizar_apps is True):
        print_log (_verbose, "Monitorizando aplicaciones")
        fvulns.monitorizarapps()

    # Buscamos vulnerabilidades segun version instalada
    if (namespace.search_vulns is True):
        print_log (_verbose, "Buscando vulnerabilidades del software instalado, segun versión instalada")
        vulnVersion()

    if (namespace.demo is True):
        print_log (_verbose, "buscamos las aplicaicones DEMO que son vulnerables")
        vulnDemo()

if __name__ == '__main__':
    main()