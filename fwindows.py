# functions windows
import horuseye
import fvulns
import winapps 

def createFile():

    fOk = open(horuseye.ConstFileAppInstaladas, 'a')
    fKo = open(horuseye.ConstFileAppNoEncontradas, 'a')
    for item in winapps.list_installed(): 
          if (item.version):
              # se saltan los que decimos que no queremos en translate
              nametemp = horuseye.miraSiTraslate(item.name)
              if (nametemp > ""):
                url =  horuseye.ConstSearchURL + nametemp
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
              nametemp = horuseye.miraSiTraslate(item.name)
              if (nametemp > ""):
                fvulns.busca_cve(nametemp, item.version)