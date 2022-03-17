import config
import fvulns

# Variables globales
listTranslate=[]


def miraSiTraslate( nom):
    result = nom
    if len(listTranslate)>0:
        for x in listTranslate:
          if (x.find(nom)!= -1):
              nametemp = x.split(";") 
              return nametemp[1].replace("\n","")
    return nom



def createFile():
    return True
    
def vulnVersion():
    return True