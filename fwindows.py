# functions windows
import fvulns
import winapps 
import config


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



def createFile( ):

    fOk = open(config.ConstFileAppInstaladas, 'a')
    fKo = open(config.ConstFileAppNoEncontradas, 'a')
    for item in winapps.list_installed(): 
          if (item.version):
              # se saltan los que decimos que no queremos en translate
              nametemp = miraSiTraslate( item.name)
              if (nametemp > ""):
                url =  config.ConstSearchURL + nametemp
                appUrl = fvulns.GetURL (url)
                if (appUrl > ""):
                    fOk.write(appUrl + '\n')
                else:
                    fKo.write(url + '\n')
    fOk.close()
    fKo.close()


def vulnVersion():
    for item in winapps.list_installed(): 
          if (item.version):
              # se saltan los que decimos que no queremos en translate
              nametemp = miraSiTraslate(item.name)
              if (nametemp > ""):
                fvulns.busca_cve(nametemp, item.version)