# SPDX-License-Identifier: MIT
"""Site defaults"""

# Version String
VERSION = '1.1.0'

# Default application vanity label
APPNAME = 'Fletchck'

# Hostname or IP to listen on
HOSTNAME = 'localhost'

# Fallback default timezone (none = localtime)
TIMEZONE = None

# Start first interval trigger this many seconds after adding
FIRSTTRIGGER = 1

# Random jitter seconds added to execution time of triggers
TRIGGERJITTER = 5

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

# Primary adminsitrator username
ADMINUSER = 'admin'

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

# DNS hostname / server
DNSHOSTNAME = '127.0.0.53'

# DNS lifetime
DNSTIMEOUT = 5

# DNS Port
DNSPORT = 53

# DNS over TCP
DNSTCP = False

# Disk full threshold (percent)
DISKLEVEL = 90

# Hysteresis for disk checks (percent)
DISKHYSTERESIS = 2

# Memory usage threshold (percent)
MEMORYLEVEL = 95

# Hysteresis for memory checks (percent)
MEMORYHYSTERESIS = 2

# Average CPU usage threshold (percent)
CPULEVEL = 75

# Hysteresis for cpu checks (percent)
CPUHYSTERESIS = 5

# Temperature warning threshold (degrees C)
TEMPLEVEL = 50

# Hysteresis for temp checks (degrees C)
TEMPHYSTERESIS = 2

# POST Endpoint for SMS Central API
SMSCENTRALURL = 'https://my.smscentral.com.au/api/v3.2'

# POST Endpoint for CK API
CKURL = 'https://sms-api.cloudkinnekt.au/smsp-in'

# Try action trigger this many times before giving up
ACTIONTRIES = 3

# Path to fallback sendmail
SENDMAIL = '/usr/lib/sendmail'

# Hide options for named check types
HIDEOPTIONS = {
    'cert': {
        'remoteId', 'level', 'volume', 'serialPort', 'hostkey', 'reqType',
        'reqPath', 'checks', 'tls', 'beeper', 'temperature', 'hysteresis',
        'reqTcp', 'reqName'
    },
    'submit': {
        'remoteId', 'level', 'volume', 'serialPort', 'hostkey', 'probe',
        'reqType', 'reqPath', 'checks', 'beeper', 'tls', 'temperature',
        'hysteresis', 'reqTcp', 'reqName'
    },
    'smtp': {
        'remoteId', 'level', 'volume', 'serialPort', 'hostkey', 'probe',
        'reqType', 'reqPath', 'checks', 'beeper', 'temperature', 'hysteresis',
        'reqTcp', 'reqName'
    },
    'imap': {
        'remoteId', 'level', 'volume', 'serialPort', 'hostkey', 'probe',
        'reqType', 'reqPath', 'checks', 'beeper', 'tls', 'temperature',
        'hysteresis', 'reqTcp', 'reqName'
    },
    'dns': {
        'remoteId', 'level', 'volume', 'serialPort', 'probe', 'hostkey',
        'reqPath', 'checks', 'beeper', 'tls', 'temperature', 'hysteresis',
        'selfsigned'
    },
    'https': {
        'remoteId', 'level', 'volume', 'serialPort', 'probe', 'hostkey',
        'checks', 'beeper', 'temperature', 'hysteresis', 'reqTcp', 'reqName'
    },
    'ssh': {
        'remoteId', 'level', 'volume', 'serialPort', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'beeper', 'temperature',
        'hysteresis', 'reqTcp', 'reqName'
    },
    'sequence': {
        'retries', 'remoteId', 'level', 'volume', 'hostname', 'port',
        'serialPort', 'timeout', 'hostkey', 'probe', 'reqType', 'reqPath',
        'selfsigned', 'tls', 'beeper', 'temperature', 'hysteresis', 'reqTcp',
        'reqName'
    },
    'remote': {
        'retries', 'publish', 'level', 'volume', 'hostname', 'port', 'hostkey',
        'probe', 'reqType', 'reqPath', 'checks', 'selfsigned', 'tls',
        'serialPort', 'beeper', 'temperature', 'hysteresis', 'reqTcp',
        'reqName'
    },
    'disk': {
        'remoteId', 'hostname', 'port', 'hostkey', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'timeout', 'serialPort',
        'beeper', 'temperature', 'reqTcp', 'reqName'
    },
    'cpu': {
        'remoteId',
        'hostname',
        'port',
        'hostkey',
        'probe',
        'reqType',
        'reqPath',
        'checks',
        'selfsigned',
        'tls',
        'timeout',
        'serialPort',
        'beeper',
        'temperature',
        'reqTcp',
        'reqName',
        'volume',
    },
    'memory': {
        'remoteId',
        'hostname',
        'port',
        'hostkey',
        'probe',
        'reqType',
        'reqPath',
        'checks',
        'selfsigned',
        'tls',
        'timeout',
        'serialPort',
        'beeper',
        'temperature',
        'reqTcp',
        'reqName',
        'volume',
    },
    'temp': {
        'remoteId', 'hostkey', 'level', 'volume', 'probe', 'reqType',
        'reqPath', 'checks', 'selfsigned', 'tls', 'serialPort', 'beeper',
        'reqTcp', 'reqName'
    },
    'ups': {
        'remoteId', 'level', 'volume', 'hostname', 'port', 'hostkey', 'probe',
        'reqType', 'reqPath', 'checks', 'selfsigned', 'tls', 'timeout',
        'temperature', 'hysteresis', 'reqTcp', 'reqName'
    },
    'upstest': {
        'remoteId', 'level', 'volume', 'hostname', 'port', 'hostkey', 'probe',
        'reqType', 'reqPath', 'checks', 'selfsigned', 'tls', 'timeout',
        'temperature', 'hysteresis', 'reqTcp', 'reqName'
    },
    'action.email': {
        'url',
        'apikey',
    },
    'action.sms': {
        'site',
        'hostname',
        'port',
        'username',
        'password',
        'timeout',
        'fallback',
    },
    'action.log': {
        'site',
        'url',
        'apikey',
        'sender',
        'recipients',
        'hostname',
        'port',
        'username',
        'password',
        'timeout',
        'fallback',
    },
}


def getOpt(key, store, valType, default=None):
    """Return value of valType from store or default"""
    ret = default
    if key in store and isinstance(store[key], valType):
        ret = store[key]
    return ret
