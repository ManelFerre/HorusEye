# import necessary packages
 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys
 
 
def enviaMail(nombre, version,  cves):
    # create message object instance
    msg = MIMEMultipart()

    # setup the parameters of the message
    password = "rjjvumbzsvnpkspg"
    msg['From'] = "horuseye.notification@gmail.com"
    msg['To'] = "horuseye.notification@gmail.com"
    msg['Subject'] = nombre + " Alerta Vulnerabilidad encotrada"
    
    # add in the message body
    textm =  "Nombre  : " + nombre + '\n' 
    textm += "Version : " + version + '\n\n\n'
    textm += '\n'.join(cves)
    msg.attach(MIMEText(textm, 'plain'))
    
    #create server
    server = smtplib.SMTP('smtp.gmail.com: 587')
    
    server.starttls()
    
    try:

        # Login Credentials for sending the mail
        server.login(msg['From'], password)

        # send the message via the server.
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
    except Exception:
        e = sys.exc_info()[1]
        print(e.args[0])