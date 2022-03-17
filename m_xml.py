from xml.dom import minidom

doc = minidom.parse("datos.xml")


# Parametros de ejecucion
nmaprun = doc.getElementsByTagName("nmaprun")[0]
#argumentos = nmaprun.getAttribute['args']
#print("argumentos: " + argumentos)

# Protocolo
#protocolo = doc.getElementsByTagName("protocol")[0]
#puertos =  doc.getElementsByTagName("services")[0].split(',')


puertos = doc.getElementsByTagName("port")
for port in puertos:
    protocol = port.getAttribute("protocol")
    portid = port.getAttribute("portid")
    print(" portid: %s" % portid)
    print(" -----protocol: %s" % protocol)

    states = port.getElementsByTagName("state")
    for state in states:
        state2 = state.getAttribute("state")
        reason = state.getAttribute("reason")
        reason_ttl = state.getAttribute("reason_ttl")
        print(" -----state: %s" % state2)
        print(" -----reason: %s" % reason)
        print(" -----reason_ttl: %s" % reason_ttl)

    services = port.getElementsByTagName("service")
    for service in services:
        name = service.getAttribute("name")
        product = service.getAttribute("product")
        version = service.getAttribute("version")
        extrainfo = service.getAttribute("extrainfo")
        ostype = service.getAttribute("ostype")
        method = service.getAttribute("method")
        print(" -----name: %s" % name)
        print(" -----product: %s" % product)
        print(" -----version: %s" % version)
        print(" -----extrainfo: %s" % extrainfo)
        print(" -----ostype: %s" % ostype)
        print(" -----method: %s" % method)

