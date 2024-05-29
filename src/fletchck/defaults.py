# SPDX-License-Identifier: MIT
"""Site defaults"""

# Version String
VERSION = '1.0.5'

# Default application vanity label
APPNAME = 'Fletchck'

# Hostname or IP to listen on
HOSTNAME = 'localhost'

# Fallback default timezone (none = localtime)
TIMEZONE = None

# Configuration filename
CONFIGPATH = 'fletchck.conf'

# SSL cert & key file names, stored in site config
SSLCERT = 'fletchck.cert'
SSLKEY = 'fletchck.key'

# Web UI config skeleton
WEBUICONFIG = {
    'name': APPNAME,
    'hostname': HOSTNAME,
    'port': None,
    'cert': None,
    'key': None,
    'debug': False,
    'users': None,
}

# MQTT Client Config
MQTTCONFIG = {
    'hostname': 'localhost',
    'port': None,
    'tls': False,
    'username': None,
    'password': None,
    'clientid': None,
    'persist': True,
    'qos': 1,
    'retain': True,
    'basetopic': None,
    'autoadd': True,
    'debug': False,
}

# Format for the volatile log
LOGFORMAT = '%(asctime)s %(message)s'

# Site CSP
CSP = "frame-ancestors 'none'; img-src data: 'self'; default-src 'self'"

# Auth cookie expiry in days
AUTHEXPIRY = 2

# Number of rounds for KDF hash
PASSROUNDS = 16

# Number of random bits in auto-generated passkeys
PASSBITS = 70

# Set of chars to use for auto-generated passkeys
# Note: Only first power of 2 used
PASSCHARS = '0123456789abcdefghjk-pqrst+vwxyz'

# SMTP check timeout
SMTPTIMEOUT = 6

# Submit check timeout
SUBMITTIMEOUT = 10

# IMAP check timeout
IMAPTIMEOUT = 6

# HTTPS check timeout
HTTPSTIMEOUT = 10

# SSH check timeout
SSHTIMEOUT = 5

# Certificate check timeout
CERTTIMEOUT = 5

# TLS certificate expiry pre-failure in days
CERTEXPIRYDAYS = 7

# POST Endpoint for SMS Central API
SMSCENTRALURL = 'https://my.smscentral.com.au/api/v3.2'

# Try action trigger this many times before giving up
ACTIONTRIES = 3

# Path to fallback sendmail
SENDMAIL = '/usr/lib/sendmail'

# Hide options for named check types
HIDEOPTIONS = {
    'cert': {
        'level', 'volume', 'serialPort', 'hostkey', 'reqType', 'reqPath',
        'checks', 'tls', 'beeper'
    },
    'submit': {
        'level', 'volume', 'serialPort', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'beeper', 'tls'
    },
    'smtp': {
        'level', 'volume', 'serialPort', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'beeper'
    },
    'imap': {
        'level', 'volume', 'serialPort', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'beeper', 'tls'
    },
    'https': {
        'level', 'volume', 'serialPort', 'probe', 'hostkey', 'checks',
        'beeper', 'tls'
    },
    'ssh': {
        'level', 'volume', 'serialPort', 'probe', 'reqType', 'reqPath',
        'checks', 'selfsigned', 'tls', 'beeper'
    },
    'sequence': {
        'level', 'volume', 'hostname', 'port', 'serialPort', 'timeout',
        'hostkey', 'probe', 'reqType', 'reqPath', 'selfsigned', 'tls', 'beeper'
    },
    'remote': {
        'level', 'volume', 'hostname', 'port', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'serialPort', 'beeper'
    },
    'disk': {
        'hostname', 'port', 'hostkey', 'probe', 'reqType', 'reqPath', 'checks',
        'selfsigned', 'tls', 'timeout', 'serialPort', 'beeper'
    },
    'ups': {
        'level', 'volume', 'hostname', 'port', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'timeout'
    },
    'upstest': {
        'level', 'volume', 'hostname', 'port', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'timeout'
    }
}


def getOpt(key, store, valType, default=None):
    """Return value of valType from store or default"""
    ret = default
    if key in store and isinstance(store[key], valType):
        ret = store[key]
    return ret
