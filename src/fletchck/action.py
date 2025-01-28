# SPDX-License-Identifier: MIT
"""Action base and specific classes"""

from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from tornado.httpclient import HTTPClient
from urllib.parse import urlencode
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate
from subprocess import run
import json

import ssl

_log = getLogger('fletchck.action')
_log.setLevel(INFO)

ACTION_TYPES = {}

_PATCH_TYPES = {
    'cksms': 'sms',
}


def loadAction(name, config):
    """Return an action object for the provided config dict"""
    ret = None
    if config['type'] in _PATCH_TYPES:
        config['type'] = _PATCH_TYPES[config['type']]
    if config['type'] in ACTION_TYPES:
        options = defaults.getOpt('options', config, dict, {})
        ret = ACTION_TYPES[config['type']](name, options)
        ret.actionType = config['type']
    else:
        _log.warning('%s: Invalid action type ignored', name)
    return ret


class BaseAction():
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

    def getBoolOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, bool, default)

    def _notify(self, source):
        _log.warning('%s (%s): %s', source.name, source.checkType,
                     source.getState())
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
        optMap = {}
        for key in self.options:
            optMap[key] = self.options[key]
        return {'type': self.actionType, 'options': optMap}


class sendEmail(BaseAction):
    """Send email by configured submit"""

    def _notify(self, source):
        site = self.getStrOpt('site', defaults.APPNAME)

        subject = "[%s] %s (%s) in %s state" % (
            site, source.name, source.checkType, source.getState())
        ml = []
        ml.append('%s (%s) in %s state at %s%s' %
                  (source.name, source.checkType, source.getState(),
                   source.lastFail if source.failState else source.lastPass,
                   '' if source.failState else '\n\U0001f436\U0001F44D'))
        if source.log:
            ml.append('')
            ml.append('Log:')
            ml.append('')
            for l in source.log:
                ml.append(l)
        message = '\n'.join(ml)
        username = self.getStrOpt('username')
        password = self.getStrOpt('password')
        sender = self.getStrOpt('sender')
        recipients = self.getListOpt('recipients', [])
        hostname = self.getStrOpt('hostname')
        fallback = self.getStrOpt('fallback')
        port = self.getIntOpt('port', 0)
        timeout = self.getIntOpt('timeout', defaults.SUBMITTIMEOUT)

        _log.debug('Send email to %r via %r : %r', recipients, hostname,
                   subject)

        ret = True
        if not recipients:
            _log.warning('No email recipients specified - notify ignored')
            return ret

        msgid = make_msgid()
        m = MIMEText(message)
        if sender:
            m['From'] = sender
        m['Subject'] = subject
        m['Message-ID'] = msgid
        m['Date'] = formatdate(localtime=True)

        if hostname:
            ret = False
            try:
                ctx = ssl.create_default_context()
                with SMTP_SSL(host=hostname,
                              port=port,
                              timeout=timeout,
                              context=ctx) as s:
                    if username and password:
                        s.login(username, password)
                    s.send_message(m, from_addr=sender, to_addrs=recipients)
                ret = True
            except Exception as e:
                _log.warning('SMTP Email Notify failed: %s', e)
        elif fallback:
            ret = False
            try:
                cmd = [fallback, '-oi']
                if sender:
                    cmd.extend(['-r', sender])
                cmd.append('--')
                cmd.extend(recipients)
                run(cmd,
                    capture_output=True,
                    input=m.as_bytes(),
                    timeout=timeout,
                    check=True)
                _log.debug('Fallback email sent ok to: %r', recipients)
                ret = True
            except Exception as e:
                _log.warning('Fallback Email Notify failed: %s', e)
        else:
            _log.warning('Email notify not configured')
        return ret


class ckSms(BaseAction):
    """Post SMS via cloudkinnect api"""

    def trigger(self, source):
        message = '%s: %s\n%s\n%s'
        if source.failState:
            message = '\U0001f436\U0001f4ac\n%s: %s\n%s\n%s' % (
                source.name,
                source.getState(),
                source.getSummary(),
                source.lastFail,
            )
        else:
            message = '\U0001f436\U0001F44D\n%s: %s\n%s' % (
                source.name,
                source.getState(),
                source.lastPass,
            )
        sender = self.getStrOpt('sender', 'dedicated')
        recipients = [i for i in self.getListOpt('recipients', [])]
        url = self.getStrOpt('url', defaults.CKURL)
        apikey = self.getStrOpt('apikey')

        httpClient = HTTPClient()
        failCount = 0
        while recipients and failCount < defaults.ACTIONTRIES:
            recipient = ','.join(recipients).replace('+', '')
            _log.debug('Send sms to %r via %r : %r', recipient, url, message)
            postBody = urlencode({
                'originator': sender,
                'mobile_number': recipient,
                'concatenated': 'true',
                'utf': 'true',
                'text': message
            })
            try:
                response = httpClient.fetch(
                    url,
                    method='POST',
                    headers={
                        'Authorization': 'Bearer ' + apikey,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body=postBody)
                if response.code == 200:
                    recipients = None
                else:
                    failCount += 1
                    _log.warning('SMS Notify failed: %r:%r', response.code,
                                 response.body)
            except Exception as e:
                failCount += 1
                _log.warning('SMS Notify failed: %s', e)
        return not recipients


ACTION_TYPES['email'] = sendEmail
ACTION_TYPES['sms'] = ckSms
ACTION_TYPES['log'] = BaseAction
