# functions windows
import horuseye
import winapps 

def createFile():

    fOk = open(horuseye.ConstFileAppInstaladas, 'a')
    fKo = open(horuseye.ConstFileAppNoEncontradas, 'a')
   
    fOk.close()
    fKo.close()