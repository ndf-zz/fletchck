# SPDX-License-Identifier: MIT
"""Machine check classes"""

from datetime import datetime
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from smtplib import SMTP
from imaplib import IMAP4_SSL
from http.client import HTTPSConnection
import ssl

_log = getLogger('check')
_log.setLevel(DEBUG)

CHECK_TYPES = {}


def timestamp():
    return datetime.now().astimezone().isoformat()


def loadCheck(name, config):
    """Create and return a check object for the provided flat config"""
    ret = None
    if config['type'] in CHECK_TYPES:
        options = {}
        if 'options' in config and isinstance(config['options'], dict):
            options = config['options']
        ret = CHECK_TYPES[config['type']](name, options)
        ret.checkType = config['type']
        if 'threshold' in config and isinstance(config['threshold'], int):
            if config['threshold'] > 0:
                ret.threshold = config['threshold']
        if 'failTrigger' in config and isinstance(config['failTrigger'], bool):
            ret.failTrigger = config['failTrigger']
        if 'passTrigger' in config and isinstance(config['passTrigger'], bool):
            ret.passTrigger = config['passTrigger']
        if 'data' in config:
            if 'failState' in config['data']:
                if isinstance(config['data']['failState'], bool):
                    ret.failState = config['data']['failState']
            if 'failCount' in config['data']:
                if isinstance(config['data']['failCount'], int):
                    if config['data']['failCount'] >= 0:
                        ret.failCount = config['data']['failCount']
            if 'threshold' in config['data']:
                if isinstance(config['data']['threshold'], int):
                    if config['data']['threshold'] >= 0:
                        ret.threshold = config['data']['threshold']
            if 'lastFail' in config['data']:
                if isinstance(config['data']['lastFail'], str):
                    ret.lastFail = config['data']['lastFail']
            if 'lastPass' in config['data']:
                if isinstance(config['data']['lastPass'], str):
                    ret.lastPass = config['data']['lastPass']
            if 'log' in config['data']:
                if isinstance(config['data']['log'], list):
                    ret.log = config['data']['log']
    else:
        _log.warning('Invalid action type ignored')
    return ret


class check():
    """Check base class"""

    def __init__(self, name, options={}):
        self.name = name
        self.failTrigger = True
        self.passTrigger = True
        self.threshold = 1
        self.options = options
        self.checkType = None

        self.actions = {}
        self.depends = {}

        self.failState = False
        self.failCount = 0
        self.log = []
        self.lastFail = None
        self.lastPass = None

    def _runCheck(self):
        """Perform the required check and return fail state"""
        return False

    def notify(self):
        """Trigger all configured actions"""
        for action in self.actions:
            self.actions[action].trigger(self)

    def update(self):
        """Run check, update state and trigger events as required"""
        for d in self.depends:
            if self.depends[d].failState:
                _log.info('%s => softfail (depends=%s)', self.name, d)
                return True

        curFail = self._runCheck()
        _log.debug('%s cur=%r prev=%r count=%r', self.name, curFail,
                   self.failState, self.failCount)

        if curFail:
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    _log.info('%s => fail', self.name)
                    self.failState = True
                    self.lastFail = timestamp()
                    if self.failTrigger:
                        self.notify()
        else:
            self.failCount = 0
            self.log.clear()
            if self.failState:
                _log.info('%s => pass', self.name)
                self.failState = False
                self.lastPass = timestamp()
                if self.passTrigger:
                    self.notify()

        return True

    def add_action(self, action):
        """Add the specified action"""
        self.actions[action.name] = action

    def del_action(self, name):
        """Remove the specified action"""
        if name in self.actions:
            del self.actions[name]

    def add_depend(self, check):
        """Add check to the set of dependencies"""
        if check is not self:
            self.depends[check.name] = check
            _log.debug('Added %s as a dep for %s', check.name, self.name)

    def del_depend(self, name):
        """Remove check from the set of dependencies"""
        if name in self.depends:
            del self.depends[name]

    def flatten(self):
        """Return the check as a flattened dictionary"""
        actList = [a for a in self.actions]
        depList = [d for d in self.depends]
        return {
            'name': self.name,
            'type': self.checkType,
            'threshold': self.threshold,
            'failTrigger': self.failTrigger,
            'passTrigger': self.passTrigger,
            'options': self.options,
            'actions': actList,
            'depends': depList,
            'data': {
                'failState': self.failState,
                'failCount': self.failCount,
                'log': self.log,
                'lastFail': self.lastFail,
                'lastPass': self.lastPass
            }
        }


class esmtpCheck(check):
    """ESMTP service check

      Connect to a SMTP server on the default port. Optionally
      verify certificate with starttls.

    """

    def _runCheck(self):
        """Perform the required check and return fail state"""
        tls = True
        if 'tls' in self.options:
            if isinstance(self.options['tls'], bool):
                tls = self.options['tls']
        hostname = None
        if 'hostname' in self.options:
            if isinstance(self.options['hostname'], str):
                hostname = self.options['hostname']

        if hostname is None:
            self.log.append('Invalid hostname')
            return True

        failState = True
        try:
            with SMTP(hostname, timeout=defaults.SMTPTIMEOUT) as s:
                ctx = ssl.create_default_context()
                if tls:
                    self.log.append(repr(s.starttls(context=ctx)))
                self.log.append(repr(s.ehlo()))
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
                failState = False
        except Exception as e:
            self.log.append('%s: %s' % (e.__class__.__name__, e))

        _log.debug('ESMTP %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class imapCheck(check):
    """IMAP4+SSL service check

      Connect to IMAP4 over SSL

    """

    def _runCheck(self):
        """Perform the required check and return fail state"""
        hostname = None
        if 'hostname' in self.options:
            if isinstance(self.options['hostname'], str):
                hostname = self.options['hostname']

        if hostname is None:
            self.log.append('Invalid hostname')
            return True

        failState = True
        try:
            ctx = ssl.create_default_context()
            with IMAP4_SSL(hostname,
                           timeout=defaults.IMAPTIMEOUT,
                           ssl_context=ctx) as i:
                self.log.append(repr(i.noop()))
                self.log.append(repr(i.logout()))
                failState = False
        except Exception as e:
            self.log.append('%s: %s' % (e.__class__.__name__, e))

        _log.debug('IMAP %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class httpsCheck(check):
    """HTTPS service check"""

    def _runCheck(self):
        """Perform the required check and return fail state"""
        sni = True
        if 'sni' in self.options:
            if isinstance(self.options['sni'], bool):
                sni = self.options['sni']
        selfsigned = False
        if 'selfsigned' in self.options:
            if isinstance(self.options['selfsigned'], bool):
                selfsigned = self.options['selfsigned']
        hostname = None
        if 'hostname' in self.options:
            if isinstance(self.options['hostname'], str):
                hostname = self.options['hostname']
        #httphost = hostname
        #if 'httphost' in self.options:
        #if isinstance(self.options['httphost'], str):
        #httphost = self.options['httphost']
        port = 443
        if 'port' in self.options:
            if isinstance(self.options['port'], int):
                port = self.options['port']

        if hostname is None:
            self.log.append('Invalid hostname')
            return True

        failState = True
        try:
            ctx = ssl.create_default_context()
            if not sni:
                ctx.check_hostname = False
            if selfsigned:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            h = HTTPSConnection(hostname,
                                port=port,
                                timeout=defaults.HTTPSTIMEOUT,
                                context=ctx)
            h.request('HEAD', '/')
            r = h.getresponse()
            self.log.append(repr((r.status, r.headers.as_string())))
            failState = False
        except Exception as e:
            self.log.append('%s: %s' % (e.__class__.__name__, e))

        _log.debug('HTTPS %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


CHECK_TYPES['esmtp'] = esmtpCheck
CHECK_TYPES['imap'] = imapCheck
CHECK_TYPES['https'] = httpsCheck
