
# Manel Ferré
# Busqueda de vulnerabilidades en el sistema operativo
#    por fecha de hoy basado en vuls-control
#    por versión, busca si la versión instalada es vulnerable

from operator import truediv
import sys

from sys import exit
from datetime import datetime
from os import remove
from os import path
import argparse

import fwindows
import flinux
import fmac
import fvulns


# Constantes
ConstURL = "https://www.cvedetails.com"
ConstSearchURL = "https://www.cvedetails.com/product-search.php?vendor_id=0&search="
ConstVersionProduct = "https://www.cvedetails.com/version-search.php?vendor=&product="
ConstVersionVersion = "version="
ConstLinkJSon = 'https://www.cvedetails.com/json-feed.php'


ConstFileAppInstaladas= "apps_local.txt"
ConstFileAppNoEncontradas = "apps_local_notfound.txt"
ConstFileSinonimos = "apps_traslate.txt"
ConstFileAppForzar = "apps_forzar.txt"
ConstDemoVulnerables = "apps_demo.txt"

# Variables globales
listTranslate=[]
listForzar=[]
listDemo=[]
today = datetime.now().strftime('%Y-%m-%d')
TextMessage = ""

sistemaOperativo = sys.platform # Detectar sistema operativo /win32/Linux/Darwin

# lee el fichero de translate para cambiar el nombre que nos dice el SO con el que tiene dado de alta CVDetails
def leeSinonimos():
    source = open(ConstFileSinonimos, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listTranslate.append(line)
    source.close()

# Aplicaciones a verificar aunque no las tengamos en el sistema
def leeAppFozar():
    source = open(ConstFileAppForzar, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listForzar.append(line)
    source.close()

# para demos, aplicaciones vulnerables
def leeAppDemoVulnerables():
    source = open(ConstDemoVulnerables, 'r')
    for line in source:
        if not line.startswith('#') and line.strip():
            listDemo.append(line)
    source.close()


def miraSiTraslate(nom):
    result = nom
    if len(listTranslate)>0:
        for x in listTranslate:
          if (x.find(nom)!= -1):
              nametemp = x.split(";") 
              return nametemp[1].replace("\n","")
    return nom



def createFile():
    if(sistemaOperativo == "win32"):
        fwindows.createFile()
    elif(sistemaOperativo == "Linux"):
        flinux.createFile()
    elif(sistemaOperativo == "Darwin"):
        fmac.createFile()


def vulnDemo():
    if len(listDemo)>0:
        for x in listDemo:
            nametemp = x.split(";") 
            fvulns.busca_cve(nametemp[0], nametemp[1])

def vulnVersionL():
    return True

def vulnVersionD():
    return True

def vulnVersion():
    if(sistemaOperativo == "win32"):
        fwindows.vulnVersion()
    elif(sistemaOperativo == "Linux"):
        vulnVersionL()
    elif(sistemaOperativo == "Darwin"):
        vulnVersionD()



def main():
    # argumentos
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', default=today, dest='DATE')
    parser.add_argument('-m', default='1', dest='MINCVSS')
    parser.add_argument('-t', default='', dest='TGTOKENID', nargs=2)

    namespace = parser.parse_args()


    if(sistemaOperativo == "win32"):
        print ("Sistema operativo Windows")
    elif(sistemaOperativo == "Linux"):
        print ("Sistema operativo Linux")
    elif(sistemaOperativo == "Darwin"):
        print ("Sistema operativo Mac")

    # borramos ficheros de apps y errores
    print ("Inicio de proceso")
    if path.exists(ConstFileAppInstaladas):        
        remove(ConstFileAppInstaladas)
    if path.exists(ConstFileAppNoEncontradas):        
        remove(ConstFileAppNoEncontradas)

    # leemos lista sinonimos
    print ("Lectura de sinónimos")
    if path.exists(ConstFileSinonimos):    
        leeSinonimos()    

    # leemos lista Aplicaciones a verificar si o si
    print ("Lectura de Aplicaciones forzadas")
    if path.exists(ConstFileAppForzar):    
        leeAppFozar()    

    # leemos lista Aplicaciones a verificar si o si
    print ("Lectura de Aplicaciones vulnerables (DEMO)")
    if path.exists(ConstDemoVulnerables):    
        leeAppDemoVulnerables()    


    # creamos el fichero de applicaciones del servidor
    print ("Creamos ficheros temporales")
    createFile()

    # Buscamos vulnerabilidades a fecha de hoy
    print ("Buscando vulnerabilidades nuevas del software instalado")
    fvulns.vuln()

    # Buscamos vulnerabilidades segun version instalada
    print ("Buscando vulnerabilidades del software instalado, segun versión instalada")
    vulnVersion()

    print("buscamos las aplicaicones DEMO que son vulnerables")
    vulnDemo()

if __name__ == '__main__':
    main()