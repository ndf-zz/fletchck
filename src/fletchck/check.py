# SPDX-License-Identifier: MIT
"""Machine check classes"""

from datetime import datetime
from zoneinfo import ZoneInfo
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from smtplib import SMTP, SMTP_SSL
from imaplib import IMAP4_SSL, IMAP4_SSL_PORT
from http.client import HTTPSConnection
from paramiko.transport import Transport as SSH
from cryptography import x509
import ssl
import socket

_log = getLogger('fletchck.check')
_log.setLevel(INFO)
getLogger('paramiko.transport').setLevel(INFO)

CHECK_TYPES = {}


def timeString(timezone=None):
    return datetime.now().astimezone(timezone).strftime("%d %b %Y %H:%M %Z")


def getZone(timezone=None):
    """Return a zoneinfo if possible"""
    ret = None
    try:
        ret = ZoneInfo(timezone)
    except Exception:
        _log.warning('Ignored invalid timezone %r', timezone)
    return ret


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


def loadCheck(name, config, timezone=None):
    """Create and return a check object for the provided flat config"""
    ret = None
    if config['type'] in CHECK_TYPES:
        options = defaults.getOpt('options', config, dict, {})
        ret = CHECK_TYPES[config['type']](name, options)
        ret.checkType = config['type']
        ret.timezone = timezone
        if 'trigger' in config and isinstance(config['trigger'], dict):
            ret.trigger = config['trigger']
        if 'threshold' in config and isinstance(config['threshold'], int):
            if config['threshold'] > 0:
                ret.threshold = config['threshold']
        if 'priority' in config and isinstance(config['priority'], int):
            ret.priority = config['priority']
        if 'failAction' in config and isinstance(config['failAction'], bool):
            ret.failAction = config['failAction']
        if 'passAction' in config and isinstance(config['passAction'], bool):
            ret.passAction = config['passAction']
        if 'timezone' in options and isinstance(options['timezone'], str):
            ret.timezone = getZone(options['timezone'])
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
            if 'lastCheck' in config['data']:
                if isinstance(config['data']['lastCheck'], str):
                    ret.lastCheck = config['data']['lastCheck']
            if 'softFail' in config['data']:
                if isinstance(config['data']['softFail'], str):
                    ret.softFail = config['data']['softFail']
            if 'log' in config['data']:
                if isinstance(config['data']['log'], list):
                    ret.log = config['data']['log']
    else:
        _log.warning('Invalid check type ignored')
    return ret


class BaseCheck():
    """Check base class"""

    def __init__(self, name, options={}):
        self.name = name
        self.failAction = True
        self.passAction = True
        self.threshold = 1
        self.priority = 0
        self.options = options
        self.checkType = None
        self.trigger = None
        self.timezone = None

        self.actions = {}
        self.depends = {}

        self.failState = True
        self.softFail = None
        self.failCount = 0
        self.log = []
        self.lastFail = None
        self.lastPass = None
        self.lastCheck = None

    def _runCheck(self):
        """Perform the required check and return fail state"""
        return False

    def getState(self):
        """Return a string indicating pass or fail"""
        if self.failState:
            return 'FAIL'
        else:
            return 'PASS'

    def notify(self):
        """Trigger all configured actions"""
        for action in self.actions:
            self.actions[action].trigger(self)

    def update(self):
        """Run check, update state and trigger events as required"""
        thisTime = timeString(self.timezone)
        self.lastCheck = thisTime
        self.softFail = None
        for d in self.depends:
            if self.depends[d].failState:
                self.softFail = d
                _log.info('%s (%s) SOFTFAIL (depends=%s) %s', self.name,
                          self.checkType, d, thisTime)
                self.log = ['SOFTFAIL (depends=%s)' % (d)]
                return True

        self.log = []
        curFail = self._runCheck()
        _log.info('%s (%s): %s curFail=%r prevFail=%r failCount=%r %s',
                  self.name, self.checkType, self.getState(), curFail,
                  self.failState, self.failCount, thisTime)

        if curFail:
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    _log.warning('%s (%s) Log: %r', self.name, self.checkType,
                                 self.log)
                    _log.warning('%s (%s) FAIL', self.name, self.checkType)
                    self.failState = True
                    self.lastFail = thisTime
                    if self.failAction:
                        self.notify()
        else:
            self.failCount = 0
            self.log.clear()
            if self.failState:
                _log.warning('%s (%s) PASS', self.name, self.checkType)
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
            _log.debug('Added dependency %s to %s', check.name, self.name)

    def del_depend(self, name):
        """Remove check from the set of dependencies"""
        if name in self.depends:
            del self.depends[name]
            _log.debug('Removed dependency %s from %s', name, self.name)

    def replace_depend(self, name, check):
        """Replace dependency with new entry if it existed"""
        if name in self.depends:
            self.del_depend(name)
            self.add_depend(check)

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
            'priority': self.priority,
            'failAction': self.failAction,
            'passAction': self.passAction,
            'options': self.options,
            'actions': actList,
            'depends': depList,
            'data': {
                'failState': self.failState,
                'failCount': self.failCount,
                'log': self.log,
                'softFail': self.softFail,
                'lastCheck': self.lastCheck,
                'lastFail': self.lastFail,
                'lastPass': self.lastPass
            }
        }


class submitCheck(BaseCheck):
    """SMTP-over-SSL / submissions check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname', '')
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


class smtpCheck(BaseCheck):
    """SMTP service check"""

    def _runCheck(self):
        tls = self.getBoolOpt('tls', True)
        hostname = self.getStrOpt('hostname', '')
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


class imapCheck(BaseCheck):
    """IMAP4+SSL service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname', '')
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


class certCheck(BaseCheck):
    """TLS Certificate check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname', '')
        port = self.getIntOpt('port')
        timeout = self.getIntOpt('timeout', defaults.CERTTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)
        probe = self.getStrOpt('probe')

        failState = True
        try:
            if not selfsigned:
                # do full TLS negotiation
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(socket.socket(socket.AF_INET),
                                       server_hostname=hostname)
                conn.settimeout(timeout)
                conn.connect((hostname, port))
                certExpiry(conn.getpeercert())
                if probe is not None:
                    self.log.append(
                        'send: %r, %r' %
                        (probe, conn.sendall(probe.encode('utf-8'))))
                    self.log.append('recv: %r' % (conn.recv(1024)))
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            else:
                pemCert = ssl.get_server_certificate(addr=(hostname, port))
                #pemCert = ssl.get_server_certificate(addr=(hostname, port), timeout=timeout)
                cert = x509.load_pem_x509_certificate(pemCert.encode('ascii'))
                expiry = cert.not_valid_after.timestamp()
                nowsecs = datetime.now().timestamp()
                daysLeft = (expiry - nowsecs) // 86400
                _log.debug('Certificate %r expiry %r: %d days', hostname,
                           cert.not_valid_after.astimezone().isoformat(),
                           daysLeft)
                if daysLeft < defaults.CERTEXPIRYDAYS:
                    raise ssl.SSLCertVerificationError(
                        'Certificate expires in %d days' % (daysLeft))
                _log.debug('%s (%s) %s: Certificate not verified', self.name,
                           self.checkType, hostname)
            failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       hostname, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, hostname,
                   failState)
        return failState


class httpsCheck(BaseCheck):
    """HTTPS service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname', '')
        port = self.getIntOpt('port')
        timeout = self.getIntOpt('timeout', defaults.HTTPSTIMEOUT)
        selfsigned = self.getBoolOpt('selfsigned', False)
        reqType = self.getStrOpt('reqType', 'HEAD')
        reqPath = self.getStrOpt('reqPath', '/')

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


class sshCheck(BaseCheck):
    """SSH service check"""

    def _runCheck(self):
        hostname = self.getStrOpt('hostname', '')
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


class sequenceCheck(BaseCheck):
    """Perform a sequence of checks in turn"""

    def __init__(self, name, options={}):
        super().__init__(name, options)
        self.checks = {}

    def add_check(self, check):
        """Add check to the sequence"""
        if check is not self:
            self.checks[check.name] = check
            _log.debug('Added check %s to sequence %s', check.name, self.name)

    def del_check(self, name):
        """Remove check from the sequence"""
        if name in self.checks:
            del self.checks[name]
            _log.debug('Removed check %s from sequence %s', name, self.name)

    def replace_check(self, name, check):
        """Replace sequence entry with new check if it existed"""
        if name in self.checks:
            self.del_check(name)
            self.add_check(check)

    def _runCheck(self):
        failState = False
        aux = []
        count = 0
        for name in self.checks:
            aux.append((self.checks[name].priority, count, name))
            count += 1
        aux.sort()
        sortedChecks = [n[2] for n in aux]

        for name in sortedChecks:
            c = self.checks[name]
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


CHECK_TYPES['cert'] = certCheck
CHECK_TYPES['smtp'] = smtpCheck
CHECK_TYPES['submit'] = submitCheck
CHECK_TYPES['imap'] = imapCheck
CHECK_TYPES['https'] = httpsCheck
CHECK_TYPES['ssh'] = sshCheck
CHECK_TYPES['sequence'] = sequenceCheck
