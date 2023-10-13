# SPDX-License-Identifier: MIT
"""Machine check classes"""

from datetime import datetime
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from smtplib import SMTP
from imaplib import IMAP4_SSL
from http.client import HTTPSConnection
import ssl
import socket
import paramiko

_log = getLogger('check')
_log.setLevel(DEBUG)

CHECK_TYPES = {}


def timestamp():
    return datetime.now().astimezone().isoformat()


def loadCheck(name, config):
    """Create and return a check object for the provided flat config"""
    ret = None
    if config['type'] in CHECK_TYPES:
        options = defaults.getOpt('options', config, dict, {})
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
                _log.info('%s => SOFTFAIL (depends=%s)', self.name, d)
                return True

        curFail = self._runCheck()
        _log.debug('%s cur=%r prev=%r count=%r', self.name, curFail,
                   self.failState, self.failCount)

        if curFail:
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    _log.info('%s => FAIL', self.name)
                    self.failState = True
                    self.lastFail = timestamp()
                    if self.failTrigger:
                        self.notify()
        else:
            self.failCount = 0
            self.log.clear()
            if self.failState:
                _log.info('%s => PASS', self.name)
                self.failState = False
                self.lastPass = timestamp()
                if self.passTrigger:
                    self.notify()

        return self.failState

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

    def getStrOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, str, default)

    def getBoolOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, bool, default)

    def getIntOpt(self, key, default=None):
        return defaults.getOpt(key, self.options, int, default)

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
        tls = self.getBoolOpt('tls', True)
        hostname = self.getStrOpt('hostname')

        if hostname is None:
            self.log.append('Invalid hostname')
            return True

        failState = True
        try:
            with SMTP(hostname, timeout=defaults.SMTPTIMEOUT) as s:
                if tls:
                    ctx = ssl.create_default_context()
                    self.log.append(repr(s.starttls(context=ctx)))
                self.log.append(repr(s.ehlo()))
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
                failState = False
        except Exception as e:
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('ESMTP %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class imapCheck(check):
    """IMAP4+SSL service check

      Connect to IMAP4 over SSL

    """

    def _runCheck(self):
        """Perform the required check and return fail state"""
        hostname = self.getStrOpt('hostname')

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
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('IMAP %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class httpsCheck(check):
    """HTTPS service check"""

    def _runCheck(self):
        """Perform the required check and return fail state"""
        checkhostname = self.getBoolOpt('checkhostname', True)
        selfsigned = self.getBoolOpt('selfsigned', False)
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', 443)

        if hostname is None:
            self.log.append('Invalid hostname')
            return True

        failState = True
        try:
            ctx = ssl.create_default_context()
            if not checkhostname:
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
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('HTTPS %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class sshCheck(check):
    """SSH service check"""

    def _runCheck(self):
        """Perform the required check and return fail state"""
        hostname = self.getStrOpt('hostname')
        hostkey = self.getStrOpt('hostkey')
        port = self.getIntOpt('port', 22)

        if not hostname or not port:
            self.log.append('Invalid hostname or port')
            return True

        failState = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((hostname, port))
                s.settimeout(defaults.SSHTIMEOUT)
                t = paramiko.Transport(s)
                t.start_client(timeout=defaults.SSHTIMEOUT)
                hk = t.get_remote_server_key().get_base64()
                self.log.append('%s:%d %r' % (hostname, port, hk))
                if hostkey is not None and hostkey != hk:
                    raise ValueError('Invalid host key %r' % (hk))
                t.close()
                failState = False
        except Exception as e:
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('SSH %s, Fail=%r, log=%r', hostname, failState, self.log)
        return failState


class sequenceCheck(check):
    """Perform a sequence of checks in turn"""

    def __init__(self, name, options={}):
        super().__init__(name, options)
        self.checks = []

    def _runCheck(self):
        failState = False
        for c in self.checks:
            cFail = c.update()
            cMsg = 'PASS'
            if cFail:
                cMsg = 'FAIL'
                self.log.append('%s (%s): %s' % (c.name, c.checkType, cMsg))
                failState = True
                self.log.extend(c.log)
                self.log.append('')
            else:
                self.log.append('%s (%s): %s' % (c.name, c.checkType, cMsg))
        _log.debug('SEQ %s, Fail=%r, log=%r', self.name, failState, self.log)
        return failState


CHECK_TYPES['esmtp'] = esmtpCheck
CHECK_TYPES['imap'] = imapCheck
CHECK_TYPES['https'] = httpsCheck
CHECK_TYPES['ssh'] = sshCheck
CHECK_TYPES['sequence'] = sequenceCheck
