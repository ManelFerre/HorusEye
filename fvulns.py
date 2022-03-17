# funciones de busqueda vulnerabilidades
import config
import requests
import notification
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from json import loads
from os import path



# Vulnerabilidad segun version : si encuentra vulnerabilidad, la muestra 
def showVuln(nombre, version, vendor_id, product_id, version_id):
    numrows = 30
    cves = []

    # "https://www.cvedetails.com/json-feed.php?vendor_id=5842&product_id=9978&version_id=663953"
    try:
        link = '{0}?vendor_id={1}&product_id={2}&version_id={3}' \
            .format(config.ConstLinkJSon, vendor_id, product_id, version_id)
        # Going to URL and get JSON
        getjson = urlopen(Request(link, headers={'User-Agent': 'Mozilla'}))
        jsonr = getjson.read()
        cves.clear()
        for y in range(0, numrows):
            try:
                jp = loads(jsonr.decode('utf-8'))[y]
                result = '{0} {1} {2}' \
                    .format(jp['cve_id'], jp['cvss_score'], jp['url'])
                tresult = 'CVSS: {0} URL: {1}' \
                    .format(jp['cvss_score'], jp['url'])
                # Keep results in arrays
                cves.append(result)
            except(IndexError):
                break
    except(ValueError, KeyError, TypeError):
        print('JSON format error')

    if len(cves) > 0: 
        notification.enviaMail(nombre, version,  cves)
        print('\n'.join(cves))


# me devuelve una lista con la misma versión, he de mirar cual de ellas es la que da vulnerabilidades
def buscaPorLista(nombre, version, url):
    try:
        r = requests.get(url)
        IniCVE = 1
        FinCVE = 0 
        LenCVE = 34
        TextCVE = ""

        while (IniCVE > 0):
              IniCVE = r.text.find('Version Details</a>&nbsp;<a href="', FinCVE)
              if (IniCVE > 0):
                    FinCVE = r.text.find('" title',IniCVE)
                    TextCVE =  r.text[IniCVE + LenCVE:FinCVE]
                    #print (TextCVE)
                    crida_json(nombre, version, TextCVE)

        if (TextCVE== ""):
              print("   Sin vulnerabilidades")
    except:
        print("Error")      

def crida_json(nombre, version, r):
        #vendor_id
        ini= r.find('vendor_id-', 0)
        fin= r.find('/', ini)
        vendor_id = r[ini + 10:fin]
        #product_id
        ini= r.find('product_id-', 0)
        fin= r.find('/', ini)
        product_id = r[ini + 11:fin]
        #version_id
        ini= r.find('version_id-', 0)
        fin= r.find('/', ini)
        version_id = r[ini + 11:fin]

        #print ("Vendor_id " + vendor_id)
        #print ("Product_id " + product_id)
        #print ("Version_id " + version_id)

        showVuln(nombre, version, vendor_id,product_id,version_id)



# busca las vulenrabilidades, puede devilver una lista
def buscaPorVersion(nombre, version, url):
    try:
        r = requests.get(url)
        IniCVE = 1
        FinCVE = 0 
        LenCVE = 25
        TextCVE = ""

        while (IniCVE > 0):
              IniCVE = r.text.find('<td nowrap><a href="/cve/', FinCVE)
              if (IniCVE > 0):
                    FinCVE = r.text.find('/"  title="CVE',IniCVE)
                    TextCVE =  r.text[IniCVE + LenCVE:FinCVE]
 #                   print (TextCVE)

        if (TextCVE== ""):
            buscaPorLista(nombre, version, url)
        else:
            crida_json(nombre, version, r.url)

    except:
        print("Error")    

# 
def GetURL(url):
    result = ""
    try:
        #url = "https://www.cvedetails.com/product-search.php?vendor_id=0&search=nginx"
        r = requests.get(url)
        aaa = r.text.find("/product/")
        aaa2 = r.text.find("?vendor_id",aaa)
        bb = r.text[aaa:aaa2]
        result = ""
        if (bb>""):
            result = config.ConstURL + bb
#            print (result)
        return result
    except:
        print("Error")



def creaListaapps(ids, fileapps):
    source = open(fileapps, 'r')
    # Buscamos el Id del producto de la lista 
    for line in source:
        if not line.startswith('#') and line.strip():
            parsed = urlparse(line)
            path = parsed[2]
            pathlist = path.split('/')
            ids.append(pathlist[2] + ';' + pathlist[3].replace('.html',''))
    source.close()



def monitorizarapps():
    date = config.today
    fecha= date.split('-')[2] + '/' + date.split('-')[1] + '/' + date.split('-')[0]
    mincvss = 1
    year = date.split('-')[0]
    month = date.split('-')[1]

    cves = []
    ids = []

    # Numero máximo de resultados
    numrows = 30

    feedlink = 'https://www.cvedetails.com/json-feed.php'

    # creamos  las listas
    creaListaapps(ids,config.ConstFileAppInstaladas)
    if path.exists(config.ConstFileAppForzar):    
        creaListaapps(ids,config.ConstFileAppForzar)

    vulencontrada = False
    # Buscamos la vulnerabilidad
    try:
        for x in ids:
            prod = x.split(';')
            # https://www.cvedetails.com/json-feed.php?product_id=47&month=02&year=2017&cvssscoremin=10&numrows=30
            link = '{0}?product_id={1}&month={2}&year={3}&cvssscoremin={4}&numrows={5}' \
                .format(feedlink, prod[0], month, year, mincvss, numrows)

            getjson = urlopen(Request(link, headers={'User-Agent': 'Mozilla'}))
            jsonr = getjson.read()
            print('Monitorizando ' + prod[1])
            for y in range(0, numrows):
                try:
                    jp = loads(jsonr.decode('utf-8'))[y]
                    if jp['publish_date'] == date:
                        result = '{0} {1} {2}' \
                            .format(jp['cve_id'], jp['cvss_score'], jp['url'])
                        tresult = 'CVSS: {0} URL: {1}' \
                            .format(jp['cvss_score'], jp['url'])
                        # guardamos el resultado en la lista
                        cves.append(result)
                except(IndexError):
                    break
            # Notificamos si hay  (una notificacion por aplicacion)
            if len(cves) != 0:
                vulencontrada = True
                print('Atencion encontradas nuevas vulnerabilidades a fecha ' + fecha)
                print('En la Aplicacion : ' + prod[1])
                print('\n'.join(cves))
                print('')
                notification.enviaMail(prod[1], '',  cves)
            else:
                print("   Sin vulnerabilidades")
            # iniciamos lista
            cves = []
        
    except(ValueError, KeyError, TypeError):
        print('JSON format error')

    if vulencontrada == False:
        print('No se han encontrado ninguna vulnerabilidad a fecha de ' + fecha)


def busca_cve (nombre, version):
      url =  config.ConstVersionProduct + nombre
      url += "&" + config.ConstVersionVersion + version
      #print (url)
      print("")
      print ("Buscando CVE de : " + nombre + " Version : " + version)

      buscaPorVersion(nombre, version, url)
      