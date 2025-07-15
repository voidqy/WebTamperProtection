import smtplib
import socket
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from logger import logger


class Alert:

    def __init__(self, config):
        self.config = config

    def alert(self, message, subject):
        """发送警报"""
        logger.warning(f"警报: {subject} - {message}")

        if self.config.get('email_enabled'):
            self.send_email(subject, message)

    def send_email(self, subject, message):
        """发送警报邮件"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)

            mail_body = MIMEText(f"服务器：{ip_address}警报: {subject} - {message}", 'plain', 'utf-8')
            msg = MIMEMultipart()
            msg['Subject'] = Header(f'网页防篡改警报: {subject}', 'utf-8')
            msg['From'] = formataddr((
                'Web Tamper Protection',
                self.config.get('from_email')
            ))
            msg['To'] = ', '.join(self.config.get('alert_emails'))
            msg.attach(mail_body)

            if self.config.get('smtp.use_tls', False):
                server = smtplib.SMTP(host=self.config.get('smtp.server'),
                                      port=int(self.config.get('smtp.port')),
                                      timeout=30)
                server.starttls()
            else:
                # 发送邮件
                server = smtplib.SMTP_SSL(
                    host=self.config.get('smtp.server'),
                    port=int(self.config.get('smtp.port')),
                    timeout=30)

            server.login(
                user=self.config.get('smtp.username'),
                password=self.config.get('smtp.password')
            )

            server.sendmail(
                from_addr=self.config.get('smtp.username'),
                to_addrs=self.config.get('alert_emails'),
                msg=msg.as_string()
            )

            logger.info("警报邮件已发送")
        except Exception as e:
            logger.error(f"发送邮件失败: {str(e)}")
