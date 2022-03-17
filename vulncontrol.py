#!/usr/bin/env python3
# https://github.com/Amet13/vulncontrol

from sys import exit
from datetime import datetime
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from json import loads
from os import remove
from os import path
import argparse

today = datetime.now().strftime('%Y-%m-%d')

# Constantes
ConstURL = "https://www.cvedetails.com"
ConstSearchURL = "https://www.cvedetails.com/product-search.php?vendor_id=0&search="
ConstFilename = "apps_local.txt"
ConstFileError = "apps_local_error.txt"

def GetURL(url):
    import requests
    result = ""
    try:
        #url = "https://www.cvedetails.com/product-search.php?vendor_id=0&search=nginx"
        r = requests.get(url)
        aaa = r.text.find("/product/")
        aaa2 = r.text.find("?vendor_id",aaa)
        bb = r.text[aaa:aaa2]
        result = ""
        if (bb>""):
            result = ConstURL + bb
            print (result)
        return result
    except:
        print("Invalid URL or some error occured while making the GET request to the specified URL")

def CreateFile():
    import subprocess
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
    llistaApp = ""
    fOk = open(ConstFilename, 'a')
    fKo = open(ConstFileError, 'a')
    try:
        for AppSerach in mylist:
            if (AppSerach > "" ):
                url =  ConstSearchURL + AppSerach
                appUrl = GetURL (url)
                if (appUrl > ""):
                    fOk.write(appUrl + '\n')
                else:
                    fKo.write(url + '\n')
    finally:
        fOk.close()
        fKo.close()
        


def Vuln():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', default=today, dest='DATE')
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
    source = open(ConstFilename, 'r')

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
        exit(0)
    else:
        print('\n'.join(cves))
        if tgtoken == '' or tgid == '':
            print('Telegram alert did not sent')
            exit(1)
        else:
            try:
                urlopen(tgfull, tgparams)
                print('Telegram alert sent')
                exit(2)
            except(HTTPError):
                print('Telegram alert did not sent, check your token and ID')
                exit(3)



def main():
    # borramos ficheros de apps y errores
    if path.exists(ConstFilename):        
        remove(ConstFilename)
    if path.exists(ConstFileError):        
        remove(ConstFileError)
    # creamos el fichero de applicaciones del servidor
    CreateFile()
    # Buscamos vulnerabilidades
    Vuln()


if __name__ == '__main__':
    main()