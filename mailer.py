"""
mailer.py
---------
Invio email transazionali (invito/attivazione account, reset password)
via SMTP (stdlib smtplib, nessuna dipendenza).

Configurazione in config.json, sezione 'smtp'. Se 'host' e' vuoto le email
sono disabilitate: le funzioni ritornano False e il chiamante espone il link
di attivazione all'admin (consegna manuale).

Le email NON contengono mai password: solo link one-time con token.
"""

import logging
import smtplib
from email.message import EmailMessage

from config import load_config

logger = logging.getLogger("vfa.mailer")


class MailError(Exception):
    """Invio fallito: SMTP non configurato o errore di consegna."""


def smtp_enabled() -> bool:
    """True se la sezione smtp ha un host configurato."""
    return bool((load_config().get("smtp") or {}).get("host"))


def _send(to_addr: str, subject: str, body: str, html: str | None = None) -> None:
    cfg = load_config()["smtp"]
    host = cfg.get("host")
    if not host:
        raise MailError("SMTP non configurato (settings -> smtp.host)")
    msg = EmailMessage()
    msg["From"] = cfg.get("from_addr") or cfg.get("username") or "vulnscan@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    try:
        with smtplib.SMTP(host, int(cfg.get("port") or 587), timeout=15) as s:
            if cfg.get("use_tls", True):
                s.starttls()
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password") or "")
            s.send_message(msg)
    except Exception as exc:
        raise MailError(f"Invio email fallito: {exc}") from exc


def _base_url() -> str:
    return (load_config()["smtp"].get("base_url") or "http://localhost:8000").rstrip("/")


def activation_link(token: str) -> str:
    return f"{_base_url()}/activate?token={token}"


# Palette email: sfondo bianco, accento arancio brand (tailwind orange-500),
# testo nero. Layout a tabelle per compatibilita' con i client di posta.
_ORANGE = "#f97316"
_BLACK = "#111111"


def _html_email(title: str, greeting: str, intro: str, button_label: str,
                link: str, ttl_line: str, footer_note: str) -> str:
    """Template HTML condiviso: logo animato in alto centrato, titolo,
    testo, bottone arancio, link in chiaro come fallback."""
    logo_url = f"{_base_url()}/static/logo-icon-animated.svg"
    return f"""\
<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#ffffff;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="background:#ffffff;font-family:Arial,Helvetica,sans-serif;">
    <tr><td align="center" style="padding:32px 16px;">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0"
             style="max-width:560px;width:100%;background:#ffffff;border:1px solid #eeeeee;border-radius:12px;">
        <tr><td align="center" style="padding:32px 32px 8px;">
          <img src="{logo_url}" width="72" height="72" alt="VULN.SCAN.O"
               style="display:block;border:0;" />
        </td></tr>
        <tr><td align="center" style="padding:0 32px 4px;">
          <span style="font-size:18px;font-weight:bold;letter-spacing:2px;color:{_BLACK};">
            VULN<span style="color:{_ORANGE};">.</span>SCAN<span style="color:{_ORANGE};">.</span><span style="color:{_ORANGE};">IO</span>
          </span>
        </td></tr>
        <tr><td style="padding:8px 32px 0;">
          <hr style="border:none;border-top:2px solid {_ORANGE};margin:0;" />
        </td></tr>
        <tr><td style="padding:24px 32px 0;">
          <h1 style="margin:0;font-size:20px;color:{_BLACK};">{title}</h1>
        </td></tr>
        <tr><td style="padding:16px 32px 0;font-size:14px;line-height:1.6;color:{_BLACK};">
          <p style="margin:0 0 12px;">{greeting}</p>
          <p style="margin:0;">{intro}</p>
        </td></tr>
        <tr><td align="center" style="padding:28px 32px;">
          <a href="{link}"
             style="display:inline-block;background:{_ORANGE};color:#ffffff;text-decoration:none;
                    font-size:14px;font-weight:bold;letter-spacing:1px;padding:12px 28px;border-radius:8px;">
            {button_label}
          </a>
        </td></tr>
        <tr><td style="padding:0 32px;font-size:12px;line-height:1.6;color:{_BLACK};">
          <p style="margin:0 0 8px;">{ttl_line}</p>
          <p style="margin:0;">If the button does not work, copy and paste this link into your browser:</p>
          <p style="margin:4px 0 0;word-break:break-all;">
            <a href="{link}" style="color:{_ORANGE};">{link}</a>
          </p>
        </td></tr>
        <tr><td style="padding:24px 32px 28px;font-size:12px;color:#555555;border-top:1px solid #eeeeee;">
          {footer_note}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""


def send_activation(to_addr: str, username: str, token: str) -> None:
    """Email di invito: link one-time per impostare la propria password."""
    link = activation_link(token)
    ttl = load_config()["auth"].get("invite_ttl_hours", 48)
    text = (
        f"Hi {username},\n\n"
        f"An account has been created for you on VULN.SCAN.O.\n"
        f"Activate it and choose your password by opening this link "
        f"(valid for {ttl} hours, single use):\n\n"
        f"  {link}\n\n"
        f"If you were not expecting this email, please ignore it.\n"
    )
    html = _html_email(
        title="Activate your account",
        greeting=f"Hi <strong>{username}</strong>,",
        intro="An account has been created for you on VULN.SCAN.O. "
              "Activate it and choose your password by clicking the button below.",
        button_label="ACTIVATE ACCOUNT",
        link=link,
        ttl_line=f"The link is valid for {ttl} hours and can be used only once.",
        footer_note="If you were not expecting this email, please ignore it.",
    )
    _send(to_addr, "VULN.SCAN.O — Activate your account", text, html)


def send_reset(to_addr: str, username: str, token: str) -> None:
    """Email di reset: link one-time per reimpostare la password."""
    link = activation_link(token)
    ttl = load_config()["auth"].get("reset_ttl_hours", 4)
    text = (
        f"Hi {username},\n\n"
        f"A password reset was requested for your VULN.SCAN.O account.\n"
        f"Reset it by opening this link (valid for {ttl} hours, single use):\n\n"
        f"  {link}\n\n"
        f"If you did not request this reset, please ignore this email: "
        f"your current password remains valid.\n"
    )
    html = _html_email(
        title="Reset your password",
        greeting=f"Hi <strong>{username}</strong>,",
        intro="A password reset was requested for your VULN.SCAN.O account. "
              "Reset it by clicking the button below.",
        button_label="RESET PASSWORD",
        link=link,
        ttl_line=f"The link is valid for {ttl} hours and can be used only once.",
        footer_note="If you did not request this reset, please ignore this email: "
                    "your current password remains valid.",
    )
    _send(to_addr, "VULN.SCAN.O — Reset your password", text, html)
