# funciones de busqueda vulnerabilidades

def busca_cve (nombre, version):
      url =  ConstVersionProduct + nombre
      url += "&" + ConstVersionVersion + version
      #print (url)
      print("")
      print ("Buscando CVE de : " + nombre + " Version : " + version)
      print (TextMessage)
      buscaPorVersion(nombre, version, url)
      