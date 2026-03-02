"""
emailer_.py — SMTP email sender with taint source/sink analysis annotations.

TAINT ANALYSIS LEGEND
─────────────────────
[SOURCE]  — entry point where untrusted / external data enters the program
[SINK]    — function / operation that consumes data in a security-relevant way
[FLOW]    — intermediate propagation of tainted data
[SANITIZE]— point where data is validated, escaped, or otherwise made safe

Security concerns surfaced by taint analysis
────────────────────────────────────────────
1. Header Injection (MEDIUM)
   If `subject`, `sender_email`, or `receiver_email` originate from user input
   and contain newlines (\r\n), an attacker can inject arbitrary MIME headers.
   Sink: MIMEMultipart.__setitem__ (msg["Subject"] = ...)

2. Credential Exposure (HIGH)
   smtp_password is hardcoded as a plaintext string literal.
   Sink: smtplib.SMTP.login()

3. Open Relay / Unvalidated Recipient (MEDIUM)
   If receiver_email comes from user input without an allowlist, this becomes
   an open mail relay.
   Sink: smtplib.SMTP.send_message()

4. STARTTLS Without Certificate Verification (LOW)
   smtplib.SMTP.starttls() uses the default SSLContext, which validates the
   server certificate. However, no explicit ssl_context is passed, so the
   trust anchors depend on the OS certificate store.
"""

import smtplib
import os
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ---------------------------------------------------------------------------
# Configuration — in a real app these should come from environment variables
# or a secrets manager, NOT be hardcoded.
# ---------------------------------------------------------------------------

# [SOURCE] These values are hardcoded here but in a real scenario they would
#          arrive from os.environ, a config file, or a web form — making them
#          untrusted sources that must be validated before use.
sender_email   = os.environ.get("SMTP_SENDER",   "you@example.com")         # [SOURCE] env var
receiver_email = os.environ.get("SMTP_RECEIVER", "recipient@example.com")   # [SOURCE] env var
subject        = os.environ.get("SMTP_SUBJECT",  "Test Email from Python")  # [SOURCE] env var
smtp_server    = os.environ.get("SMTP_HOST",     "smtp.example.com")        # [SOURCE] env var
smtp_port      = int(os.environ.get("SMTP_PORT", "587"))
smtp_user      = os.environ.get("SMTP_USER",     "you@example.com")         # [SOURCE] env var

# [SOURCE] Credential from environment — still a source; must never be logged or echoed
smtp_password  = os.environ.get("SMTP_PASSWORD", "your_password")           # [SOURCE] credential


# ---------------------------------------------------------------------------
# Sanitisation helper — strip CR/LF to prevent MIME header injection
# ---------------------------------------------------------------------------
def sanitize_header(value: str) -> str:
    """
    [SANITIZE] Remove carriage-return and newline characters that could be
    used to inject additional MIME headers (header injection attack).
    """
    # Strip any embedded newlines — this is the critical sanitisation step
    cleaned = re.sub(r"[\r\n]+", " ", value).strip()  # [SANITIZE]
    return cleaned


def validate_email_address(addr: str) -> bool:
    """
    [SANITIZE] Basic structural validation of an email address.
    Not a full RFC 5322 parser, but sufficient to reject obvious injections.
    """
    pattern = r"^[^@\s<>;]+@[^@\s<>;]+\.[^@\s<>;]{2,}$"
    return bool(re.match(pattern, addr))  # [SANITIZE]


# ---------------------------------------------------------------------------
# Validate sources before they reach sinks
# ---------------------------------------------------------------------------
if not validate_email_address(sender_email):          # [SANITIZE] guard
    raise ValueError(f"Invalid sender address: {sender_email!r}")

if not validate_email_address(receiver_email):        # [SANITIZE] guard
    raise ValueError(f"Invalid receiver address: {receiver_email!r}")

# Sanitise header fields to prevent injection
safe_subject  = sanitize_header(subject)              # [SANITIZE] → taint cleared for subject
safe_sender   = sanitize_header(sender_email)         # [SANITIZE] → taint cleared for From
safe_receiver = sanitize_header(receiver_email)       # [SANITIZE] → taint cleared for To


# ---------------------------------------------------------------------------
# Build the MIME message
# ---------------------------------------------------------------------------
msg = MIMEMultipart()

# [FLOW] sanitised values flow into MIME header fields
# [SINK] MIMEMultipart.__setitem__ writes to MIME headers; if unsanitised data
#        reaches here an attacker can inject extra headers (e.g. Bcc: ...).
msg["From"]    = safe_sender    # [SINK] — safe because sanitize_header() was called
msg["To"]      = safe_receiver  # [SINK] — safe because sanitize_header() was called
msg["Subject"] = safe_subject   # [SINK] — safe because sanitize_header() was called

# Email body — plain text; no HTML rendering, so XSS is not applicable here.
body = "Hello, this is a test email sent using Python's email package."

# [FLOW] body is static here; if it were user-controlled it would need
#        sanitisation before being passed to MIMEText.
msg.attach(MIMEText(body, "plain"))   # [FLOW] body → MIMEText (safe — static string)


# ---------------------------------------------------------------------------
# Send via SMTP
# ---------------------------------------------------------------------------
server = None  # initialise so finally-block is safe even if constructor raises

try:
    # [SINK] smtplib.SMTP() opens a TCP connection to smtp_server:smtp_port.
    #        If smtp_server is user-controlled this could be used for SSRF.
    server = smtplib.SMTP(smtp_server, smtp_port)   # [SINK] network connection

    # [SINK] starttls() upgrades the connection to TLS.
    #        Without an explicit ssl_context this trusts the OS certificate store.
    server.starttls()   # [SINK] TLS upgrade

    # [SINK] login() transmits smtp_user and smtp_password over the TLS channel.
    #        The credential (smtp_password) is a [SOURCE] from the environment;
    #        it must never be logged or echoed in error messages.
    server.login(smtp_user, smtp_password)   # [SINK] credential transmitted — keep out of logs!

    # [SINK] send_message() delivers the email.
    #        If receiver_email were unvalidated this would be an open relay.
    server.send_message(msg)   # [SINK] email delivered
    print("✅ Email sent successfully!")

except smtplib.SMTPAuthenticationError:
    # Avoid logging smtp_password even in error paths
    print("❌ Authentication failed. Check SMTP_USER / SMTP_PASSWORD env vars.")
except smtplib.SMTPException as e:
    print(f"❌ SMTP error: {e}")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
finally:
    if server:
        server.quit()