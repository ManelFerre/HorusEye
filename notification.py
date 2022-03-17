 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys
 
 
def enviaMail(nombre, version,  cves):
    # instanciamos
    msg = MIMEMultipart()

    # Paramentros conexion
    password = "jjvumbzsvnpkspgr"
    msg['From'] = "horuseye.notification@gmail.com"
    msg['To'] = "manel.ferre@tecdes.es"
    msg['Subject'] = nombre + " Alerta Vulnerabilidad encotrada"
    
    # mensaje
    textm =  "Nombre  : " + nombre + '\n' 
    textm += "Version : " + version + '\n\n\n'
    textm += '\n'.join(cves)
    msg.attach(MIMEText(textm, 'plain'))
    
    #Servidor
    server = smtplib.SMTP('smtp.gmail.com: 587')
    
    server.starttls()
    
    try:

        # Login 
        server.login(msg['From'], password)

        # enviamos mensaje
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
    except Exception:
        e = sys.exc_info()[1]
        print('Error : ' + e.args[0] + ' al enviar mensaje')