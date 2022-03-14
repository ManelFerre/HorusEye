# funciones de busqueda vulnerabilidades
import horuseye
import requests
import notification
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from json import loads
import argparse



# si encuentra vulnerabilidad, la muestra
def showVuln(nombre, version, vendor_id, product_id, version_id):
    numrows = 30
    cves = []
    tgcves = []

    # "https://www.cvedetails.com/json-feed.php?vendor_id=5842&product_id=9978&version_id=663953"
    try:
        link = '{0}?vendor_id={1}&product_id={2}&version_id={3}' \
            .format(horuseye.ConstLinkJSon, vendor_id, product_id, version_id)
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
                tgcves.append(tresult)
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
              print("Sin vulnerabilidades")
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
            result = horuseye.ConstURL + bb
#            print (result)
        return result
    except:
        print("Error")



    

def vuln():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', default=horuseye.today, dest='DATE')
    parser.add_argument('-m', default='1', dest='MINCVSS')
    parser.add_argument('-t', default='', dest='TGTOKENID', nargs=2)

    namespace = parser.parse_args()

    try:
        tgtoken = namespace.TGTOKENID[0]
        tgid = namespace.TGTOKENID[1]
    except(IndexError):
        tgtoken = ''
        tgid = ''

    date = namespace.DATE
    mincvss = namespace.MINCVSS
    year = date.split('-')[0]
    month = date.split('-')[1]

    ids = []
    cves = []
    tgcves = []

    # Maximum rows for one product
    numrows = 30

    tgurl = 'https://api.telegram.org/bot'
    tgfull = '{0}{1}/sendMessage'.format(tgurl, tgtoken)
    feedlink = 'https://www.cvedetails.com/json-feed.php'
    source = open(horuseye.ConstFileAppInstaladas, 'r')

    # Getting product IDs from file
    for line in source:
        if not line.startswith('#') and line.strip():
            parsed = urlparse(line)
            path = parsed[2]
            pathlist = path.split('/')
            ids.append(pathlist[2])
    source.close()

    # Get JSON
    try:
        for x in ids:
            # Link example:
            # https://www.cvedetails.com/json-feed.php?product_id=47&month=02&year=2017&cvssscoremin=10&numrows=30
            link = '{0}?product_id={1}&month={2}&year={3}&cvssscoremin={4}&numrows={5}' \
                .format(feedlink, x, month, year, mincvss, numrows)
            # Going to URL and get JSON
            getjson = urlopen(Request(link, headers={'User-Agent': 'Mozilla'}))
            jsonr = getjson.read()
            for y in range(0, numrows):
                try:
                    jp = loads(jsonr.decode('utf-8'))[y]
                    if jp['publish_date'] == date:
                        result = '{0} {1} {2}' \
                            .format(jp['cve_id'], jp['cvss_score'], jp['url'])
                        tresult = 'CVSS: {0} URL: {1}' \
                            .format(jp['cvss_score'], jp['url'])
                        # Keep results in arrays
                        cves.append(result)
                        tgcves.append(tresult)
                except(IndexError):
                    break
    except(ValueError, KeyError, TypeError):
        print('JSON format error')

    # Getting data for Telegram
    tgdata = '{0} report:\n{1}'.format(date, '\n'.join(tgcves))
    tgparams = urlencode({'chat_id': tgid, 'text': tgdata}).encode('utf-8')

    if len(cves) == 0:
        print('There are no available vulnerabilities on ' + date)
#        exit(0)
    else:
        print('\n'.join(cves))
        if tgtoken == '' or tgid == '':
            print('Telegram alert did not sent')
#            exit(1)
        else:
            try:
                urlopen(tgfull, tgparams)
                print('Telegram alert sent')
                exit(2)
            except(HTTPError):
                print('Telegram alert did not sent, check your token and ID')
#                exit(3)




def busca_cve (nombre, version):
      url =  horuseye.ConstVersionProduct + nombre
      url += "&" + horuseye.ConstVersionVersion + version
      #print (url)
      print("")
      print ("Buscando CVE de : " + nombre + " Version : " + version)

      buscaPorVersion(nombre, version, url)
      