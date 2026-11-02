"""发邮件（docs/自动执行.md「邮件」）。

只发给配置好的收件组（页面上加的，或服务器上写的）：调用方只能给组名，地址、SMTP 账号和授权码都在 automation_config 里。
465（ssl，一连上就是 TLS）和 587（starttls，先明文再升级）都支持；证书照常校验，内网自签的证书用 mail.ca_file。
连接、超时这类临时失败重试（一共 3 次）；登录被拒、发件人被拒这类重试也没用的，不重试。日志里不写授权码。
"""
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app import automation_config
from app.config import log

RETRY_DELAYS = (5, 30)        # 第一次失败后等 5 秒，第二次失败后等 30 秒，一共试 3 次


class MailError(RuntimeError):
    """没发出去。说明是中文、不带密钥，可以直接给页面看。"""

    def __init__(self, message, attempts=0):
        super().__init__(message)
        self.attempts = attempts


def reason(exc) -> str:
    """异常 → 给人看的原因。不带 SMTP 主机和账号：原因会写进执行记录和日志，那里用不着它们。"""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return f"登录被拒绝：账号或授权码不对（SMTP {exc.smtp_code}）"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return f"发件人被拒绝：mail.from 一般要和登录账号一致（SMTP {exc.smtp_code}）"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "收件人全部被拒收：检查收件组里的地址"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "SMTP 服务器不支持这种加密方式或登录方式：465 端口用 ssl，587 端口用 starttls"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS 证书校验没过：服务器证书不受信任（内网自签证书用 mail.ca_file 指定 CA）"
    if isinstance(exc, ssl.SSLError):
        return "TLS 握手失败：多半是加密方式和端口不配（465 用 ssl，587 用 starttls）"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "连接 SMTP 服务器超时（出站端口可能被封：云主机常封 25，换 465 或 587）"
    if isinstance(exc, ConnectionRefusedError):
        return "SMTP 服务器拒绝连接：端口不对，或服务器没开"
    if isinstance(exc, socket.gaierror):
        return "找不到 SMTP 服务器：mail.host 写错了或 DNS 不通"
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"SMTP 服务器拒绝（{exc.smtp_code}）"
    if isinstance(exc, (smtplib.SMTPException, OSError)):
        return f"发送失败：{exc.__class__.__name__}"
    return f"发送失败：{exc.__class__.__name__}"


def _permanent(exc) -> bool:
    """重试也没用的失败：登录、发件人、收件人被拒，加密方式不支持，证书不受信任。"""
    if isinstance(exc, (smtplib.SMTPAuthenticationError, smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused,
                        smtplib.SMTPNotSupportedError, ssl.SSLCertVerificationError, socket.gaierror)):
        return True
    return isinstance(exc, smtplib.SMTPResponseException) and 500 <= exc.smtp_code < 600


def _context(mail):
    return ssl.create_default_context(cafile=mail.ca_file or None)


def _deliver(mail, message, recipients):
    if mail.security == "ssl":
        client = smtplib.SMTP_SSL(mail.host, mail.port, timeout=mail.timeout, context=_context(mail))
    else:
        client = smtplib.SMTP(mail.host, mail.port, timeout=mail.timeout)
    try:
        client.ehlo()
        if mail.security == "starttls":
            client.starttls(context=_context(mail))
            client.ehlo()
        if mail.user:
            client.login(mail.user, mail.password)
        client.send_message(message, from_addr=mail.sender_addr, to_addrs=list(recipients))
    finally:
        try:
            client.quit()
        except Exception:
            client.close()


def build(mail, recipients, subject, text, html) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail.sender
    message["To"] = ", ".join(recipients)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=mail.sender_addr.rsplit("@", 1)[-1])
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def send(group, subject, text, html="", settings=None, sleep=time.sleep, delays=None) -> dict:
    """发给收件组 group。成功返回 {status: sent, attempts, recipients}；失败抛 MailError（带试了几次）。"""
    delays = RETRY_DELAYS if delays is None else delays
    settings = settings or automation_config.load()
    if settings.mail is None:
        raise MailError(f"发件设置用不了：{settings.mail_problem}" if settings.mail_problem else
                        "还没有配置发件邮箱（SMTP）：在「SOP → 自动执行 → 邮件」里设置，或写在服务器上的配置文件里")
    recipients = settings.groups.get(group)
    if not recipients:
        raise MailError(f"没有收件组「{group}」：可能已经删掉了，到计划或告警规则里重新选一个")
    message = build(settings.mail, recipients, subject, text, html)
    attempts, last = 0, ""
    for attempt in range(len(delays) + 1):
        attempts += 1
        try:
            _deliver(settings.mail, message, recipients)
        except Exception as exc:
            last = reason(exc)
            log.warning("mail to group %s failed (attempt %d): %s", group, attempts, last)
            if _permanent(exc) or attempt >= len(delays):
                break
            sleep(delays[attempt])
            continue
        log.info("mail sent to group %s (%d recipients, attempt %d): %s", group, len(recipients), attempts, subject[:120])
        return {"status": "sent", "attempts": attempts, "recipients": len(recipients)}
    raise MailError(last or "发送失败", attempts)
