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

_log = getLogger('fletcher.action')
_log.setLevel(DEBUG)

ACTION_TYPES = {}


def loadAction(name, config):
    """Return an action object for the provided config dict"""
    ret = None
    if config['type'] in ACTION_TYPES:
        options = defaults.getOpt('options', config, dict, {})
        ret = ACTION_TYPES[config['type']](name, options)
        ret.actionType = config['type']
    else:
        _log.warning('%s: Invalid action type ignored', name)
    return ret


class action():
    """Action base class, implements the log type and interface"""

    def __init__(self, name=None, options={}):
        self.name = name
        self.options = options
        self.actionType = 'log'

    def getStrOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, str, default)

    def getIntOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, int, default)

    def getListOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, list, default)

    def _notify(self, source):
        msg = 'PASS'
        since = source.lastPass
        if source.failState:
            msg = 'FAIL'
            since = source.lastFail
        _log.info('%s: %s %s @ %s', self.name, source.name, msg, since)
        return True

    def trigger(self, source):
        count = 0
        while True:
            if self._notify(source):
                break
            count += 1
            if count >= defaults.ACTIONTRIES:
                _log.error('%s (%s): Fail after %r tries', self.name,
                           self.actionType, count)
                return False
        return True

    def flatten(self):
        """Return the action detail as a flattened dictionary"""
        return {'type': self.actionType, 'options': self.options}


class sendEmail(action):
    """Send email by configured submit"""

    def _notify(self, source):
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
        recipients = self.getListOpt('recipients', [])
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', 0)
        timeout = self.getIntOpt('timeout', defaults.SUBMITTIMEOUT)

        _log.debug('Send email to %r via %r : %r', recipients, hostname,
                   subject)
        ret = True
        if hostname and username and recipients and sender:
            ret = False
            try:
                msgid = make_msgid()
                m = MIMEText(message)
                m['From'] = sender
                m['Subject'] = subject
                m['Message-ID'] = msgid
                m['Date'] = formatdate(localtime=True)
                ctx = ssl.create_default_context()
                with SMTP_SSL(host=hostname,
                              port=port,
                              timeout=timeout,
                              context=ctx) as s:
                    s.login(username, password)
                    s.send_message(m, from_addr=sender, to_addrs=recipients)
                ret = True
            except Exception as e:
                _log.warning('Email Notify failed: %s', e)
        return ret


class apiSms(action):
    """Post SMS via smscentral api"""

    def _notify(self, source):
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
        ret = True
        if recipient and url:
            ret = False
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
                if response.body == b'0':
                    ret = True
                else:
                    _log.warning('SMS Notify failed: %r:%r', response.code,
                                 response.body)
            except Exception as e:
                _log.warning('SMS Notify failed: %s', e)
        return ret


class dbusSms(action):
    """Post sms with ModemManager via dbus"""
    pass


ACTION_TYPES['log'] = action
ACTION_TYPES['email'] = sendEmail
ACTION_TYPES['sms'] = apiSms
ACTION_TYPES['mm'] = dbusSms
