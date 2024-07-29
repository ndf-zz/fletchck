# SPDX-License-Identifier: MIT
"""Machine check classes"""

from datetime import datetime
from zoneinfo import ZoneInfo
from dateutil.parser import parse as dateparse
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR
from smtplib import SMTP, SMTP_SSL
from imaplib import IMAP4_SSL, IMAP4_SSL_PORT
from http.client import HTTPSConnection
from paramiko.transport import Transport as SSH
from threading import Lock
from cryptography import x509
from .ups import UpsQsV
from shutil import disk_usage
import ssl
import socket

_log = getLogger('fletchck.check')
_log.setLevel(INFO)
getLogger('paramiko.transport').setLevel(INFO)

CHECK_TYPES = {}
_TERA = 1024 * 1024 * 1024 * 1024
_GIGA = 1024 * 1024 * 1024

# Serial port locks
_serialLock = {'': Lock()}

# Temporary: Common local timezone labels
LOCALZONES = {
    "AEST": +36000,
    "AEDT": +39600,
    "ACST": +34200,
    "ACDT": +37800,
}


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
        if 'subType' in config and isinstance(config['subType'], str):
            ret.subType = config['subType']
        if 'priority' in config and isinstance(config['priority'], int):
            ret.priority = config['priority']
        if 'failAction' in config and isinstance(config['failAction'], bool):
            ret.failAction = config['failAction']
        if 'passAction' in config and isinstance(config['passAction'], bool):
            ret.passAction = config['passAction']
        if 'publish' in config and isinstance(config['publish'], str):
            ret.publish = config['publish']
        if 'timezone' in options and isinstance(options['timezone'], str):
            ret.timezone = getZone(options['timezone'])
        if 'data' in config:
            if 'failState' in config['data']:
                if isinstance(config['data']['failState'], (bool, str)):
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
            if 'lastUpdate' in config['data']:
                if isinstance(config['data']['lastUpdate'], str):
                    ret.lastUpdate = config['data']['lastUpdate']
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
        self.publish = None
        self.threshold = 1
        self.priority = 0
        self.options = options
        self.checkType = None
        self.subType = None
        self.trigger = None
        self.timezone = None

        self.actions = {}
        self.depends = {}

        self.failState = True
        self.softFail = None
        self.failCount = 0
        self.log = []
        self.oldLog = None
        self.lastFail = None
        self.lastPass = None
        self.lastCheck = None
        self.lastUpdate = None

    def _runCheck(self):
        """Perform the required check and return fail state"""
        return False

    def getState(self):
        """Return a string indicating pass or fail"""
        if self.failState:
            return 'FAIL'
        else:
            return 'PASS'

    def getSummary(self):
        """Return a short text summary of the check state"""
        ret = ''
        if self.failState and self.log:
            ret = self.log[-1]
        return ret

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

        self.oldLog = self.log
        self.log = []
        curFail = self._runCheck()
        _log.info('%s (%s): %s curFail=%r prevFail=%r failCount=%r %s',
                  self.name, self.checkType, self.getState(), curFail,
                  self.failState, self.failCount, thisTime)

        if curFail:
            self.failCount += 1
            if self.failCount >= self.threshold:
                # compare fail state by value
                if curFail != self.failState:
                    _log.warning('%s (%s) Log: %r', self.name, self.checkType,
                                 self.log)
                    _log.warning('%s (%s) FAIL', self.name, self.checkType)
                    self.failState = curFail
                    self.lastFail = thisTime
                    if self.failAction:
                        self.notify()
        else:
            self.failCount = 0
            if self.failState:
                _log.warning('%s (%s) PASS', self.name, self.checkType)
                self.failState = curFail
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

    def msgObj(self):
        """Return a remote notification object for this check"""
        return {
            'name': self.name,
            'type': self.checkType,
            'data': {
                'threshold': self.threshold,
                'failState': self.failState,
                'failCount': self.failCount,
                'log': self.log,
                'softFail': self.softFail,
                'lastCheck': self.lastCheck,
                'lastFail': self.lastFail,
                'lastPass': self.lastPass
            }
        }

    def flatten(self):
        """Return the check as a flattened dictionary"""
        actList = [a for a in self.actions]
        depList = [d for d in self.depends]
        return {
            'type': self.checkType,
            'subType': self.subType,
            'trigger': self.trigger,
            'threshold': self.threshold,
            'priority': self.priority,
            'failAction': self.failAction,
            'passAction': self.passAction,
            'publish': self.publish,
            'options': self.options,
            'actions': actList,
            'depends': depList,
            'data': {
                'failState': self.failState,
                'failCount': self.failCount,
                'log': self.log,
                'softFail': self.softFail,
                'lastCheck': self.lastCheck,
                'lastUpdate': self.lastUpdate,
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
                failState = False
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
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
                failState = False
                self.log.append(repr(s.noop()))
                self.log.append(repr(s.quit()))
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
                sock = socket.create_connection((hostname, port),
                                                timeout=timeout)
                conn = ctx.wrap_socket(sock, server_hostname=hostname)
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
            with socket.create_connection((hostname, port),
                                          timeout=timeout) as s:
                t = SSH(s)
                t.start_client(timeout=timeout)
                hk = t.get_remote_server_key().get_base64()
                self.log.append('%s:%d %r' % (hostname, port, hk))
                if hostkey is not None and hostkey != hk:
                    raise ValueError('Invalid host key')
                elif hostkey is None:
                    _log.info('%s (%s) %s: Adding hostkey=%s', self.name,
                              self.checkType, hostname, hk)
                    self.options['hostkey'] = hk
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


class upsStatus(BaseCheck):
    """UPS basic check"""

    def _runCheck(self):
        serialPort = self.getStrOpt('serialPort', '')
        if serialPort:
            if serialPort not in _serialLock:
                with _serialLock['']:
                    _serialLock[serialPort] = Lock()
        beeper = self.getBoolOpt('beeper', True)

        failState = True
        try:
            _log.debug('Waiting for serialport')
            with _serialLock[serialPort]:
                u = UpsQsV(serialPort)
                u.setBeeper(beeper)
                self.log.append('Load: %d%%, Battery: %0.1fV' %
                                (u.load, u.battery))
                self.log.append(u.getInfo(update=False))
                if u.lowBattery:
                    self.log.append('Low battery warning: %0.1fV' %
                                    (u.battery))
                failState = (u.error or u.fail or u.fault or u.lowBattery
                             or u.shutdown)
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       serialPort, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' %
                            (serialPort, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType,
                   serialPort, failState)
        return failState


class upsTest(BaseCheck):
    """Run a UPS self-test and check result"""

    def _runCheck(self):
        serialPort = self.getStrOpt('serialPort', '')
        if serialPort:
            if serialPort not in _serialLock:
                with _serialLock['']:
                    _serialLock[serialPort] = Lock()

        failState = True
        try:
            _log.debug('Waiting for serialport')
            with _serialLock[serialPort]:
                u = UpsQsV(serialPort)
                failState, msg = u.runTest()
                self.log.append(msg)
                _log.info('%s (%s) %s: %s', self.name, self.checkType,
                          serialPort, msg)
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       serialPort, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' %
                            (serialPort, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType,
                   serialPort, failState)
        return failState


class remoteCheck(BaseCheck):
    """A check that receives state from a remote fletch over MQTT"""

    def _runCheck(self):
        thisTime = datetime.now().astimezone(self.timezone)
        timeout = self.getIntOpt('timeout', None)
        failState = self.failState
        et = 0
        if timeout and self.lastUpdate:
            lu = dateparse(self.lastUpdate,
                           tzinfos=LOCALZONES).astimezone(self.timezone)
            et = (thisTime - lu).total_seconds()
            if et > timeout:
                _log.debug('%s (%s): Timeout waiting for update %d sec / %s',
                           self.name, self.checkType, et, self.lastUpdate)
                self.log.append('Timeout waiting for update %d sec (%s)' %
                                (et, self.lastUpdate))
                failState = True
            else:
                # restore remote log if non-empty
                if self.oldLog:
                    self.log = self.oldLog
        return failState

    def remoteUpdate(self, checkType, data):
        """Report remote transition (replicates baseCheck.update)"""
        self.subType = checkType
        doNotify = False
        if data['failState']:
            if data['failCount'] >= data['threshold']:
                if data['failState'] != self.failState:
                    _log.warning('%s (%s.%s) Log: %r', self.name,
                                 self.checkType, self.subType, data['log'])
                    _log.warning('%s (%s.%s) FAIL', self.name, self.checkType,
                                 self.subType)
                    if self.failAction:
                        doNotify = True
        else:
            if self.failState:
                _log.warning('%s (%s.%s) PASS', self.name, self.checkType,
                             self.subType)
                if self.passAction:
                    doNotify = True

        # Check last update field
        lastUpdate = timeString(self.timezone)
        if 'lastCheck' in data and data['lastCheck']:
            # verify value as a datestring
            try:
                lu = dateparse(data['lastCheck'],
                               tzinfos=LOCALZONES).astimezone(self.timezone)
                lastUpdate = data['lastCheck']
            except Exception:
                _log.info('%s (%s.%s): Ignored invalid last update time',
                          self.name, self.checkType, self.subType)

        # Overwrite state from remote data
        self.failState = data['failState']
        self.lastUpdate = lastUpdate
        self.failCount = data['failCount']
        self.threshold = data['threshold']
        self.log = data['log']
        self.softFail = data['softFail']
        self.lastCheck = data['lastCheck']
        self.lastFail = data['lastFail']
        self.lastPass = data['lastPass']
        if doNotify:
            self.notify()


class diskCheck(BaseCheck):
    """Check a disk volume for free space"""

    # todo: add disk heath reporting where available
    def _runCheck(self):
        volume = self.getStrOpt('volume', '/')
        level = self.getIntOpt('level', 90)

        failState = True
        try:
            du = disk_usage(volume)
            dpct = 100.0 * du.used / du.total
            if du.total > 0.8 * _TERA:
                msg = '%s (%s) %s: %2.0f%% %0.2f/%0.2fTiB, %0.2fTiB Free' % (
                    self.name, self.checkType, volume, dpct, du.used / _TERA,
                    du.total / _TERA, du.free / _TERA)
            else:
                msg = '%s (%s) %s: %2.0f%% %0.0f/%0.0fGiB, %0.0fGiB Free' % (
                    self.name, self.checkType, volume, dpct, du.used / _GIGA,
                    du.total / _GIGA, du.free / _GIGA)

            self.log.append(msg)
            if dpct < level:
                failState = False
        except Exception as e:
            _log.debug('%s (%s) %s %s: %s Log=%r', self.name, self.checkType,
                       volume, e.__class__.__name__, e, self.log)
            self.log.append('%s %s: %s' % (hostname, e.__class__.__name__, e))

        _log.debug('%s (%s) %s: Fail=%r', self.name, self.checkType, volume,
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

    def getSummary(self):
        ret = ''
        if self.failState:
            rv = []
            for check in self.failState.split(','):
                rv.append(' %s \u26a0\ufe0f' % (check, ))
            if rv:
                ret = '\n'.join(rv)
        return ret

    def _runCheck(self):
        failChecks = set()
        aux = []
        count = 0
        for name in self.checks:
            aux.append((self.checks[name].priority, count, name))
            count += 1
        aux.sort()
        sortedChecks = [n[2] for n in aux]

        # Perform each check in order
        for name in sortedChecks:
            c = self.checks[name]
            cFail = c.update()
            cMsg = 'PASS'
            if cFail:
                failChecks.add(c.name)
                cMsg = 'FAIL'
                self.log.append('%s (%s): %s' % (c.name, c.checkType, cMsg))
                self.log.extend(c.log)
                self.log.append('')
            else:
                self.log.append('%s (%s): %s' % (c.name, c.checkType, cMsg))

        _log.debug('%s (%s): Fail=%r', self.name, self.checkType, failChecks)

        # Prepare ordered list of failing checks
        rv = []
        for name in sortedChecks:
            if name in failChecks:
                rv.append(name)
        return ','.join(rv)


CHECK_TYPES['cert'] = certCheck
CHECK_TYPES['smtp'] = smtpCheck
CHECK_TYPES['submit'] = submitCheck
CHECK_TYPES['imap'] = imapCheck
CHECK_TYPES['https'] = httpsCheck
CHECK_TYPES['ssh'] = sshCheck
CHECK_TYPES['sequence'] = sequenceCheck
CHECK_TYPES['ups'] = upsStatus
CHECK_TYPES['upstest'] = upsTest
CHECK_TYPES['remote'] = remoteCheck
CHECK_TYPES['disk'] = diskCheck
