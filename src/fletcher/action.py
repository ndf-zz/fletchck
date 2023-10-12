# SPDX-License-Identifier: MIT
"""Action base and specific classes"""

from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from tornado.httpclient import HTTPClient
from urllib.parse import urlencode
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate

import ssl

_log = getLogger('action')
_log.setLevel(DEBUG)

ACTION_TYPES = {}


def loadAction(name, config):
    """Return an action object for the provided config dict"""
    ret = None
    if config['type'] in ACTION_TYPES:
        options = {}
        if 'options' in config and isinstance(config['options'], dict):
            options = config['options']
        ret = ACTION_TYPES[config['type']](name, options)
        ret.actionType = config['type']
    else:
        _log.warning('Invalid action type ignored')
    return ret


class action():
    """Action base class, implements the log type and interface"""

    def __init__(self, name=None, options={}):
        self.name = name
        self.options = options
        self.actionType = 'log'

    def getStrOpt(self, key, default=None):
        ret = default
        if key in self.options and isinstance(self.options[key], str):
            ret = self.options[key]
        return ret

    def trigger(self, source):
        """Fire the action with the provided context"""
        msg = 'PASS'
        since = source.lastPass
        if source.failState:
            msg = 'FAIL'
            since = source.lastFail
        _log.info('%s: %s %s @ %s', self.name, source.name, msg, since)
        return True

    def flatten(self):
        """Return the action detail as a flattened dictionary"""
        return {
            'name': self.name,
            'options': self.options,
            'type': self.actionType
        }


class sendEmail(action):
    """Send email by configured submit"""

    def trigger(self, source):
        if source.failState:
            subject = "[%s] %s in FAIL state" % (self.name, source.name)
            ml = []
            ml.append('%s in FAIL state at %s' %
                      (source.name, source.lastFail))
            ml.append('')
            ml.append('Log:')
            ml.append('')
            for l in source.log:
                ml.append(l)
            message = '\n'.join(ml)
        else:
            subject = "[%s] %s in PASS state" % (self.name, source.name)
            message = '%s in PASS state at %s\n\U0001F4A9\U0001F44D' % (
                source.name, source.lastPass)
        username = self.getStrOpt('username')
        password = self.getStrOpt('password')
        sender = self.getStrOpt('sender')
        recipient = self.getStrOpt('recipient')
        mta = self.getStrOpt('mta')

        _log.debug('Send email to %r via %r : %r', recipient, mta, subject)
        if mta and username and recipient and sender:
            try:
                msgid = make_msgid()
                m = MIMEText(message)
                m['From'] = sender
                m['To'] = recipient
                m['Subject'] = subject
                m['Message-ID'] = msgid
                m['Date'] = formatdate(localtime=True)
                with SMTP_SSL(mta) as s:
                    s.login(username, password)
                    s.send_message(m)
            except Exception as e:
                _log.error('Notify failed: %s', e)


class apiSms(action):
    """Post SMS via smscentral api"""

    def trigger(self, source):
        if source.failState:
            message = "%s in FAIL state at %s" % (source.name, source.lastFail)
        else:
            message = "%s in PASS state at %s\n\U0001F4A9\U0001F44D" % (
                source.name, source.lastPass)
        sender = self.getStrOpt('sender', 'dedicated')
        recipient = self.getStrOpt('recipient')
        username = self.getStrOpt('username')
        password = self.getStrOpt('password')
        url = self.getStrOpt('url', defaults.SMSCENTRALURL)

        _log.debug('Send sms to %r via %r : %r', recipient, url, message)
        if recipient and url:
            postBody = urlencode({
                'ACTION': 'send',
                'USERNAME': username,
                'PASSWORD': password,
                'ORIGINATOR': sender,
                'RECIPIENT': recipient,
                'MESSAGE_TEXT': message
            })
            httpClient = HTTPClient()
            try:
                response = httpClient.fetch(
                    url,
                    method='POST',
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body=postBody)
            except Exception as e:
                _log.error('Notify failed: %s', e)


class dbusSms(action):
    """Post sms with ModemManager via dbus"""
    pass


ACTION_TYPES['log'] = action
ACTION_TYPES['email'] = sendEmail
ACTION_TYPES['sms'] = apiSms
ACTION_TYPES['mm'] = dbusSms
