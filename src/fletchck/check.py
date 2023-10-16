# SPDX-License-Identifier: MIT
"""Machine check classes"""

from datetime import datetime
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from smtplib import SMTP, SMTP_SSL
from imaplib import IMAP4_SSL, IMAP4_SSL_PORT
from http.client import HTTPSConnection
from paramiko.transport import Transport as SSH
import ssl
import socket

_log = getLogger('fletchck.check')
_log.setLevel(DEBUG)
getLogger('paramiko.transport').setLevel(WARNING)

CHECK_TYPES = {}


def timestamp():
    return datetime.now().astimezone().isoformat()


def certExpiry(cert):
    """Raise SSL certificate error if about to expire"""
    if cert is not None and 'notAfter' in cert:
        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
        nowsecs = datetime.now().timestamp()
        daysLeft = (expiry - nowsecs) // 86400
        _log.debug('Certificate %r expiry %r: %d days', cert['subject'],
                   cert['notAfter'], daysLeft)
        if daysLeft < defaults.CERTEXPIRYDAYS:
            raise ssl.SSLCertVerificationError(
                'Certificate expires in %d days' % (daysLeft))
    else:
        _log.debug('Certificate missing - expiry check skipped')
    return True


def loadCheck(name, config):
    """Create and return a check object for the provided flat config"""
    ret = None
    if config['type'] in CHECK_TYPES:
        options = defaults.getOpt('options', config, dict, {})
        ret = CHECK_TYPES[config['type']](name, options)
        ret.checkType = config['type']
        if 'trigger' in config and isinstance(config['trigger'], dict):
            ret.trigger = config['trigger']
        if 'threshold' in config and isinstance(config['threshold'], int):
            if config['threshold'] > 0:
                ret.threshold = config['threshold']
        if 'failAction' in config and isinstance(config['failAction'], bool):
            ret.failAction = config['failAction']
        if 'passAction' in config and isinstance(config['passAction'], bool):
            ret.passAction = config['passAction']
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
        _log.warning('Invalid check type ignored')
    return ret


class check():
    """Check base class"""

    def __init__(self, name, options={}):
        self.name = name
        self.failAction = True
        self.passAction = True
        self.threshold = 1
        self.options = options
        self.checkType = None
        self.trigger = None

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
        thisTime = timestamp()
        for d in self.depends:
            if self.depends[d].failState:
                _log.info('%s (%s) SOFTFAIL (depends=%s) %s', self.name,
                          self.checkType, d, thisTime)
                self.log = ['SOFTFAIL (depends=%s)' % (d)]
                return True

        self.log = []
        curFail = self._runCheck()
        _log.debug('%s (%s): curFail=%r prevFail=%r failCount=%r %s',
                   self.name, self.checkType, curFail, self.failState,
                   self.failCount, thisTime)

        if curFail:
            _log.info('%s (%s) FAIL %s', self.name, self.checkType, thisTime)
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    self.failState = True
                    self.lastFail = thisTime
                    if self.failAction:
                        self.notify()
        else:
            _log.info('%s (%s) PASS %s', self.name, self.checkType, thisTime)
            self.failCount = 0
            self.log.clear()
            if self.failState:
                self.failState = False
                self.lastPass = thisTime
                if self.passAction:
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
            'type': self.checkType,
            'trigger': self.trigger,
            'threshold': self.threshold,
            'failAction': self.failAction,
            'passAction': self.passAction,
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


class submitCheck(check):
    """SMTP-over-SSL / submissions check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', 0)
        timeout = self.getIntOpt('timeout', defaults.SUBMITTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)

        failState = True
        try:
            ctx = ssl.create_default_context()
            if selfsigned:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with SMTP_SSL(host=hostname,
                          port=port,
                          timeout=timeout,
                          context=ctx) as s:
                self.log.append(repr(s.ehlo()))
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
                failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
        return failState


class smtpCheck(check):
    """SMTP service check"""

    def _runCheck(self):
        tls = self.getBoolOpt('tls', True)
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', 0)
        timeout = self.getIntOpt('timeout', defaults.SMTPTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)

        failState = True
        try:
            with SMTP(host=hostname, port=port, timeout=timeout) as s:
                if tls:
                    ctx = ssl.create_default_context()
                    if selfsigned:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    self.log.append(repr(s.starttls(context=ctx)))
                    certExpiry(s.sock.getpeercert())
                self.log.append(repr(s.ehlo()))
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
                failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
        return failState


class imapCheck(check):
    """IMAP4+SSL service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', IMAP4_SSL_PORT)
        timeout = self.getIntOpt('timeout', defaults.IMAPTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)

        failState = True
        try:
            ctx = ssl.create_default_context()
            if selfsigned:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with IMAP4_SSL(host=hostname,
                           port=port,
                           ssl_context=ctx,
                           timeout=defaults.IMAPTIMEOUT) as i:
                certExpiry(i.sock.getpeercert())
                self.log.append(repr(i.noop()))
                self.log.append(repr(i.logout()))
                failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
        return failState


class httpsCheck(check):
    """HTTPS service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port')
        timeout = self.getIntOpt('timeout', defaults.HTTPSTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)
        reqType = self.getStrOpt('request', 'HEAD')
        reqPath = self.getStrOpt('path', '/')

        failState = True
        try:
            ctx = ssl.create_default_context()
            if selfsigned:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            h = HTTPSConnection(host=hostname,
                                port=port,
                                timeout=defaults.HTTPSTIMEOUT,
                                context=ctx)
            h.request(reqType, reqPath)
            certExpiry(h.sock.getpeercert())
            r = h.getresponse()
            self.log.append(repr((r.status, r.headers.as_string())))
            failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
        return failState


class sshCheck(check):
    """SSH service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname')
        port = self.getIntOpt('port', 22)
        timeout = self.getIntOpt('timeout', defaults.SSHTIMEOUT)
        hostkey = self.getStrOpt('hostkey')

        failState = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((hostname, port))
                t = SSH(s)
                t.start_client(timeout=timeout)
                hk = t.get_remote_server_key().get_base64()
                self.log.append('%s:%d %r' % (hostname, port, hk))
                if hostkey is not None and hostkey != hk:
                    raise ValueError('Invalid host key')
                self.log.append('ignore: %r' % (t.send_ignore()))
                self.log.append('close: %r' % (t.close()))
                failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
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

        _log.debug('%s (%s): Fail=%r', self.name, self.checkType, failState)
        return failState


CHECK_TYPES['smtp'] = smtpCheck
CHECK_TYPES['submit'] = submitCheck
CHECK_TYPES['imap'] = imapCheck
CHECK_TYPES['https'] = httpsCheck
CHECK_TYPES['ssh'] = sshCheck
CHECK_TYPES['sequence'] = sequenceCheck
