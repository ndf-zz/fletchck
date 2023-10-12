# SPDX-License-Identifier: MIT
"""Site defaults"""

# Default application vanity label
APPNAME = 'Fletcher'

# Hostname or IP to listen on
HOSTNAME = 'localhost'

# Path to configuration from site base
CONFIGPATH = 'config'

# Path to application static files from site base
STATICPATH = 'static'

# Path to html template files from site base
TEMPLATEPATH = 'templates'

# SSL cert & key file names, stored in site config
SSLCERT = 'cert'
SSLKEY = 'key'

# Site config skeleton
CONFIG = {
    'debug': True,
    'cert': None,
    'key': None,
    'host': HOSTNAME,
    'name': APPNAME,
    'base': None,
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
SMTPTIMEOUT = 5

# IMAP check timeout
IMAPTIMEOUT = 5

# HTTPS check timeout
HTTPSTIMEOUT = 10

# POST Endpoint for SMS Central API
SMSCENTRALURL = 'https://my.smscentral.com.au/api/v3.2'
