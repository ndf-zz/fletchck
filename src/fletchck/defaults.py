# SPDX-License-Identifier: MIT
"""Site defaults"""

# Default application vanity label
APPNAME = 'Fletchck'

# Hostname or IP to listen on
HOSTNAME = 'localhost'

# Configuration filename
CONFIGPATH = 'fletchck.conf'

# SSL cert & key file names, stored in site config
SSLCERT = 'fletchck.cert'
SSLKEY = 'fletchck.key'

# Web UI config skeleton
WEBUICONFIG = {
    'debug': False,
    'cert': None,
    'key': None,
    'host': HOSTNAME,
    'name': APPNAME,
    'port': None,
    'users': None,
}

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


def getOpt(key, store, valType, default=None):
    """Return value of valType from store or default"""
    ret = default
    if key in store and isinstance(store[key], valType):
        ret = store[key]
    return ret
