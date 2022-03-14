# functions windows
import horuseye

def createFile():


    fOk = open(horuseye.ConstFileAppInstaladas, 'a')
    fKo = open(horuseye.ConstFileAppNoEncontradas, 'a')
   
    fOk.close()
    fKo.close()