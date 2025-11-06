import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_Server = 'smtp.gmail.com'
SMTP_ID = 'guksuukim57@gmail.com'
SMTP_PW = 'wnuc vlhq izyg gonq'
SMTP_SSL = False
SMTP_PORT = 465
FROM_NAME = "guksuukim57"
FROM_EMAIL = "guksuukim57@gmail.com"
TO_EMAIL = "root@redhat12.xyz"
SUBJECT = "Test Email"
BODY = "This is a test email sent from Python."

def send_email():
    # Create the email
    msg = MIMEMultipart()
    msg['From'] = '{} <{}>'.format(FROM_NAME, FROM_EMAIL)
    msg['To'] = TO_EMAIL
    msg['Subject'] = SUBJECT
    msg.attach(MIMEText(BODY, 'plain'))

    # Connect to the server
    server = smtplib.SMTP_SSL(SMTP_Server, SMTP_PORT)
    server.login(SMTP_ID, SMTP_PW)
    
    # Send the email
    server.sendmail(FROM_EMAIL, TO_EMAIL, msg.as_string())
    server.quit()

# Call the function to send email
send_email()

