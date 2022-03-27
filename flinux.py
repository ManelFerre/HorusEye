import config
import fvulns
import subprocess

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
    #dpkg -l | grep ^ii | awk '{print $2, $3}'  

    p1cmd=["dpkg","-l"]
    p2cmd=["grep","^ii"]
    p3cmd=['awk','{print $2}']

    p1=subprocess.Popen(p1cmd,stdout=subprocess.PIPE)
    p2=subprocess.Popen(p2cmd,stdin=p1.stdout, stdout=subprocess.PIPE)
    p3=subprocess.Popen(p3cmd,stdin=p2.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    p2.stdout.close()
    output = p3.communicate()[0]
    #print(output.decode('utf-8').replace(":amd64",""))
    mylist = output.decode('utf-8').replace(":amd64","").split("\n")
    fOk = open(config.ConstFileAppInstaladas, 'a')
    fKo = open(config.ConstFileAppNoEncontradas, 'a')
    try:
        for AppSearch in mylist:
            if (AppSearch > "" ):
                # se saltan los que decimos que no queremos en translate
                nametemp = miraSiTraslate(AppSearch)
                if (nametemp > ""):
                    url =  config.ConstSearchURL + nametemp
                    appUrl = fvulns.GetURL (url)
                    if (appUrl > ""):
                        fOk.write(appUrl + '\n')
                    else:
                        fKo.write(url + '\n')
    finally:
        fOk.close()
        fKo.close()

def vulnVersion():
    #dpkg -l | grep ^ii | awk '{print $2, $3}'  

    p1cmd=["dpkg","-l"]
    p2cmd=["grep","^ii"]
    p3cmd=['awk','{print $2, $3}']

    p1=subprocess.Popen(p1cmd,stdout=subprocess.PIPE)
    p2=subprocess.Popen(p2cmd,stdin=p1.stdout, stdout=subprocess.PIPE)
    p3=subprocess.Popen(p3cmd,stdin=p2.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    p2.stdout.close()
    output = p3.communicate()[0]
    #print(output.decode('utf-8').replace(":amd64",""))
    mylist = output.decode('utf-8').replace(":amd64","").split("\n")
   
    for AppSearch in mylist:
        if (AppSearch > "" ):
            # se saltan los que decimos que no queremos en translate
            nametemp = miraSiTraslate(AppSearch)
            if (nametemp > ""):
                url =  config.ConstSearchURL + nametemp
                appUrl = fvulns.GetURL (url)
#                if (appUrl > ""):
#                    fvulns.busca_cve(nametemp, item.version)
  