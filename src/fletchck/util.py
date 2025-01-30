# SPDX-License-Identifier: MIT
"""Application support utilities"""

import os
import re
import sys
import csv
import json
import struct
import math
from datetime import datetime, timedelta, UTC
from secrets import randbits, token_hex
from passlib.hash import argon2 as kdf
from tempfile import NamedTemporaryFile, mkdtemp
from logging import getLogger, Handler, DEBUG, INFO, WARNING
from subprocess import run
from ipaddress import IPv6Address
from . import defaults
from .action import loadAction
from .check import loadCheck, getZone, BaseCheck, timeString
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

_log = getLogger('fletchck.util')
_log.setLevel(DEBUG)
getLogger('apscheduler.executors').setLevel(INFO)
getLogger('apscheduler.executors.default').setLevel(INFO)

_INTTRIGKEYS = {
    'weeks',
    'days',
    'hours',
    'minutes',
    'seconds',
}
_INTERVALKEYS = {
    'weeks': 'week',
    'days': 'day',
    'hours': 'hr',
    'minutes': 'min',
    'seconds': 'sec',
    'end_date': 'end',
    'timezone': 'z',
}
_CRONKEYS = {
    'year': 'year',
    'month': 'month',
    'day': 'day',
    'week': 'week',
    'day_of_week': 'weekday',
    'hour': 'hr',
    'minute': 'min',
    'second': 'sec',
    'end_date': 'end',
    'timezone': 'z',
}
_BOOLVALS = {
    't': True,
    'f': False,
    '1': True,
    '0': False,
    'true': True,
    'false': False,
    'yes': True,
    'no': False,
    'null': False,
    'none': False,
    '': False,
}


class SaveFile():
    """Tempfile-backed save file contextmanager.

       Creates a temporary file with the desired mode and encoding
       and returns a context manager and writable file handle.

       On close, the temp file is atomically moved to the provided
       filename (if possible).
    """

    def __init__(self,
                 filename,
                 mode='t',
                 encoding='utf-8',
                 tempdir='.',
                 perm=0o600):
        self.__sfile = filename
        self.__path = tempdir
        self.__perm = perm
        if mode == 'b':
            encoding = None
        self.__tfile = NamedTemporaryFile(mode='w' + mode,
                                          suffix='.tmp',
                                          prefix='sav_',
                                          dir=self.__path,
                                          encoding=encoding,
                                          delete=False)

    def __enter__(self):
        return self.__tfile

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__tfile.close()
        if exc_type is not None:
            return False  # raise exception
        # otherwise, file is saved ok in temp file
        os.chmod(self.__tfile.name, self.__perm)
        os.rename(self.__tfile.name, self.__sfile)
        return True


class LogHandler(Handler):

    def __init__(self, site):
        self.site = site
        Handler.__init__(self)

    def emit(self, record):
        """Append record to log and prune early entries"""
        msg = self.format(record)
        self.site.log.append(msg)
        if len(self.site.log) > 200:
            del (self.site.log[0:10])


def toBool(boolstr):
    key = boolstr.lower()
    if key in _BOOLVALS:
        return _BOOLVALS[key]
    if key.isdigit():
        return bool(int(key))
    else:
        return bool(key)


def toHostname(hostname):
    """Check hostname for MAC or unscoped ipv6 ll"""
    if isMacAddr(hostname):
        # assume EUI-64 LL address desired
        hostname = mac2ll(hostname)
    elif ':' in hostname:
        # assume ipv6 - check for LL without scope
        hostname = lladdscope(hostname)
    else:
        # probably hostname or v4
        pass
    return hostname


def isMacAddr(hostname):
    """Return true if hostname looks like a MAC address"""
    return re.match('^[\dA-Fa-f]{2}(:[\dA-Fa-f]{2}){5}$', hostname) is not None


def lladdscope(address):
    """Append interface 2 to LL address if scope not provided"""
    ret = address
    try:
        va = IPv6Address(address)
        if va.is_link_local and va.scope_id is None:
            ret = '%s%%2' % (va, )
    except Exception as e:
        _log.info('Invalid ipv6 address %s: %s', e.__class__.__name__, e)
    return ret


def mac2ll(macaddr, interface='2'):
    """Convert MAC address to EUI-64 link-local addr on interface 2"""
    ret = macaddr
    try:
        if isMacAddr(macaddr):
            leui48 = int(macaddr.replace(':', ''), 16) | 1 << 41
            llval = 0xfe80 << 112 | 0xfffe << 24 | (
                leui48 & 0xffffff000000) << 16 | leui48 & 0xffffff
            ##addr = IPv6Address(llval)
            ret = '%s%%%s' % (IPv6Address(llval), interface)
    except Exception as e:
        _log.info('Invalid MAC address %s: %s', e.__class__.__name__, e)
    return ret


def trigger2Text(trigger):
    """Convert a trigger schedule object to text string"""
    rv = []
    if isinstance(trigger, dict):
        if 'interval' in trigger:
            rv.append('interval')
            for key in _INTERVALKEYS:
                if key in trigger['interval']:
                    rv.append(str(trigger['interval'][key]))
                    rv.append(_INTERVALKEYS[key])
        elif 'cron' in trigger:
            rv.append('cron')
            for key in _CRONKEYS:
                if key in trigger['cron']:
                    rv.append(str(trigger['cron'][key]))
                    rv.append(_CRONKEYS[key])
    return ' '.join(rv)


def text2Trigger(triggerText):
    """Read, validate and return trigger definition"""
    ret = None
    try:
        trigger = None
        if triggerText:
            tv = triggerText.lower().split()
            if tv:
                # check type prefix
                trigType = tv[0]
                if trigType == 'interval':
                    tv.pop(0)
                    trigger = {'interval': {}}
                elif trigType == 'cron':
                    tv.pop(0)
                    trigger = {'cron': {}}
                else:
                    _log.debug('text2Trigger: Assuming interval for %r', tv)
                    trigger = {'interval': {}}

                keyMap = {}
                trigMap = None
                if 'interval' in trigger:
                    trigMap = trigger['interval']
                    for k in _INTERVALKEYS:
                        keyMap[k] = k
                        keyMap[_INTERVALKEYS[k]] = k
                elif 'cron' in trigger:
                    trigMap = trigger['cron']
                    for k in _CRONKEYS:
                        keyMap[k] = k
                        keyMap[_CRONKEYS[k]] = k

                # scan input text
                nextVal = []
                while tv:
                    # check for value:
                    if tv[0] in keyMap:
                        _log.debug('Ignoring spurious unit %s', tv[0])
                        tv.pop(0)
                        continue

                    nextVal.append(tv.pop(0))
                    if tv:
                        if tv[0] in keyMap:
                            unit = tv.pop(0)
                            val = ' '.join(nextVal)
                            key = keyMap[unit]
                            if key in _INTTRIGKEYS:
                                val = int(val)
                            if key in trigMap:
                                _log.debug('Trigger key %s re-defined', key)
                            trigMap[key] = val
                            nextVal = []
                if nextVal:
                    # Lazily assume minutes for degenerate input
                    val = ' '.join(nextVal)
                    _log.debug(
                        'Extra value without units %s, assuming minutes', val)
                    key = keyMap['min']
                    if key in _INTTRIGKEYS:
                        val = int(val)
                    if key in trigMap:
                        _log.debug('Trigger key %s re-defined', key)
                    trigMap[key] = val
                    nextVal = []

                # try and create a trigger from the definition
                if 'interval' in trigger:
                    t = IntervalTrigger(**trigMap)
                elif 'cron' in trigger:
                    t = CronTrigger(**trigMap)

                ret = trigger
    except Exception as e:
        _log.info('Invalid trigger %s: %s', e.__class__.__name__, e)
    return ret


def checkPass(pw, hash):
    return kdf.verify(pw, hash[0:1024])


def createHash(pw):
    return kdf.using(rounds=defaults.PASSROUNDS).hash(pw)


def randPass():
    """Return a random passkey"""
    choiceLen = len(defaults.PASSCHARS)
    if choiceLen < 8:
        raise RuntimeError('Unexpected length passchars')
    depth = int(math.floor(math.log2(choiceLen)))
    clen = 2**depth
    if clen != choiceLen:
        _log.warning('Using first %r chars of passchars', clen)
    passLen = int(math.ceil(defaults.PASSBITS / depth))
    rawBits = randbits(passLen * depth)
    mask = clen - 1
    pv = []
    for i in range(0, passLen):
        pv.append(defaults.PASSCHARS[rawBits & mask])
        rawBits >>= depth
    return ''.join(pv)


def saveSite(site):
    """Save the current site state to disk"""
    dstCfg = {'base': site.base, 'timezone': None, 'webui': None}
    if site.timezone is not None:
        dstCfg['timezone'] = site.timezone.key
    if site.webCfg is not None:
        dstCfg['webui'] = {}
        for k in defaults.WEBUICONFIG:
            dstCfg['webui'][k] = site.webCfg[k]
    if site.mqttCfg is not None:
        dstCfg['mqtt'] = {}
        for k in defaults.MQTTCONFIG:
            dstCfg['mqtt'][k] = site.mqttCfg[k]
    dstCfg['actions'] = {}
    for a in site.actions:
        dstCfg['actions'][a] = site.actions[a].flatten()
    dstCfg['checks'] = {}
    for c in site.checks:
        dstCfg['checks'][c] = site.checks[c].flatten()
    dstCfg['log'] = site.log

    # backup existing config and save
    tmpName = None
    if os.path.exists(site.configFile):
        tmpName = site.configFile + token_hex(6)
        os.link(site.configFile, tmpName)
    with SaveFile(site.configFile) as f:
        json.dump(dstCfg, f, indent=1)
    if tmpName is not None:
        os.rename(tmpName, site.configFile + '.bak')
    _log.debug('Saved site config to %r', site.configFile)


def readCsv(csvFile):
    """Read CSV file and return a check config."""
    checkOpts = (
        'trigger',
        'paused',
        'threshold',
        'retries',
        'priority',
        'failAction',
        'passAction',
        'publish',
        'remoteId',
        'timezone',
    )
    specialOpts = (
        'name',
        'checkType',
        'depends',
        'actions',
        'checks',
        'inseq',
    )
    optionTypes = {
        'trigger': text2Trigger,
        'paused': toBool,
        'threshold': int,
        'retries': int,
        'priority': int,
        'failAction': toBool,
        'passAction': toBool,
        'timezone': getZone,
        'hostname': toHostname,
        'port': int,
        'tls': toBool,
        'selfsigned': toBool,
        'level': int,
        'timeout': int,
        'temperature': int,
        'reqName': str,
        'reqPath': str,
        'reqType': str,
        'probe': str,
        'hostkey': str,
        'serialPort': str,
        'volume': str,
        'reqTcp': toBool,
        'beeper': toBool,
        'hysteresis': int,
    }
    inseq = {}
    hdr = None
    dat = []
    cfg = {'checks': {}}
    cr = csv.reader(csvFile)

    # read in csv rows to intermediate key:value with converted values
    for r in cr:
        if hdr is None:
            # assume first row is header
            hdr = [c.strip() for c in r]
            if 'name' not in hdr or 'checkType' not in hdr:
                _log.error('CSV missing required columns: name, checkType')
                raise RuntimeError(
                    'CSV missing required headers: name, checkType')
        else:
            count = 0
            chk = {}
            for c in r:
                c = c.strip()
                if c != '':
                    key = hdr[count]
                    val = c
                    if key in optionTypes:
                        val = optionTypes[key](c)
                    chk[key] = val
                count += 1
            if chk['checkType'] == 'sequence':
                inseq[chk['name']] = []
            dat.append(chk)

    # convert intermediate options into check configs
    for chk in dat:
        checkName = chk['name']
        checkType = chk['checkType']
        checkCfg = {"type": checkType}
        for key in checkOpts:
            if key in chk:
                checkCfg[key] = chk[key]
        if 'depends' in chk:
            checkCfg['depends'] = []
            for dep in chk['depends'].split(','):
                dep = dep.strip()
                if dep:
                    checkCfg['depends'].append(dep)
        if 'actions' in chk:
            checkCfg['actions'] = []
            for dep in chk['actions'].split(','):
                dep = dep.strip()
                if dep:
                    checkCfg['actions'].append(dep)
        checkCfg['options'] = {}
        for key in chk:
            if key not in specialOpts and key not in checkOpts:
                checkCfg['options'][key] = chk[key]
        if 'checks' in chk:
            checkCfg['options']['checks'] = []
            for dep in chk['checks'].split(','):
                dep = dep.strip()
                if dep:
                    checkCfg['options']['checks'].append(dep)
        if 'inseq' in chk:
            checkCfg['inseq'] = []
            for dep in chk['inseq'].split(','):
                dep = dep.strip()
                if dep:
                    checkCfg['inseq'].append(dep)
        cfg['checks'][checkName] = checkCfg
    _log.debug('Read %d check entries from CSV file', len(cfg['checks']))
    return cfg


def mergeCsv(path, config, csvFilename):
    """Import checks from csv file and merge with site config"""
    importFilename = os.path.realpath(csvFilename)
    cfgFilename = os.path.join(path, config)
    if os.path.samefile(cfgFilename, importFilename):
        _log.warning('Ignored CSV import from existing config')
        return
    if os.path.exists(importFilename):
        _log.info('Importing checks from CSV %r', importFilename)
        try:
            importConf = None
            with open(importFilename) as f:
                importConf = readCsv(f)
            cfgConf = None
            with open(cfgFilename) as f:
                cfgConf = json.load(f)
            if mergeCfg(importConf, cfgConf):
                _log.info('Saving updated config')
                tmpName = None
                if os.path.exists(cfgFilename):
                    tmpName = cfgFilename + token_hex(6)
                    os.link(cfgFilename, tmpName)
                with SaveFile(cfgFilename) as f:
                    json.dump(cfgConf, f, indent=1)
                if tmpName is not None:
                    os.rename(tmpName, cfgFilename + '.bak')
            else:
                _log.warning('No updates imported')
        except Exception as e:
            _log.warning('Ignored invalid import, %s: %s',
                         e.__class__.__name__, e)
            raise e
    else:
        _log.warning('CSV checks import file not found, ignored')


def mergeCfg(importConf, cfgConf):
    """Copy values from importConf dict to cfgConf dict."""
    doSave = False
    if 'timezone' in importConf:
        _log.info('Imported timezone')
        cfgConf['timezone'] = importConf['timezone']
        doSave = True
    if 'webui' in importConf and importConf['webui'] is not None:
        if 'webui' not in cfgConf or not isinstance(cfgConf['webui'], dict):
            cfgConf['webui'] = {}
        dst = cfgConf['webui']
        src = importConf['webui']
        for key in src:
            if key == 'users':
                if 'users' not in dst or not isinstance(dst['users'], dict):
                    dst['users'] = {}
                for user in src['users']:
                    if user == defaults.ADMINUSER and defaults.ADMINUSER in dst[
                            'users']:
                        _log.warning('Admin user not updated')
                    else:
                        dst['users'][user] = src['users'][user]
            else:
                dst[key] = src[key]
        _log.info('Imported webui config')
        doSave = True
    if 'mqtt' in importConf:
        if 'mqtt' not in cfgConf:
            cfgConf['mqtt'] = {}
        dst = cfgConf['mqtt']
        src = importConf['mqtt']
        for key in src:
            dst[key] = src[key]
        _log.info('Imported mqtt config')
        doSave = True
    if 'actions' in importConf:
        for action in importConf['actions']:
            if action not in cfgConf['actions']:
                cfgConf['actions'][action] = {}
            destAction = cfgConf['actions'][action]
            srcAction = importConf['actions'][action]
            if 'type' in srcAction:
                destAction['type'] = srcAction['type']
            if 'options' in srcAction:
                if 'options' not in destAction:
                    destAction['options'] = {}
                for key in srcAction['options']:
                    destAction['options'][key] = srcAction['options'][key]
            _log.info('Imported action: %s', action)
            doSave = True
    inseq = {}
    if 'checks' in importConf:
        for checkName in importConf['checks']:
            if checkName not in cfgConf['checks']:
                cfgConf['checks'][checkName] = {}
            destCheck = cfgConf['checks'][checkName]
            srcCheck = importConf['checks'][checkName]
            for key in srcCheck:
                if key != 'data' and key != 'inseq':
                    destCheck[key] = srcCheck[key]
            if 'inseq' in srcCheck:
                for seqName in srcCheck['inseq']:
                    if seqName:
                        if seqName not in inseq:
                            inseq[seqName] = []
                    if checkName not in inseq[seqName]:
                        inseq[seqName].append(checkName)
            _log.info('Imported check: %s', checkName)
            doSave = True
    for seqName in inseq:
        if seqName in cfgConf['checks']:
            seq = cfgConf['checks'][seqName]
            if seq['type'] == 'sequence':
                if 'checks' not in seq['options']:
                    seq['options']['checks'] = []
                for checkName in inseq[seqName]:
                    if checkName not in seq['options']['checks']:
                        seq['options']['checks'].append(checkName)
                        _log.debug('Added %s to sequence %s', checkName,
                                   seqName)
                        doSave = True
            else:
                _log.warning('Named inseq not a sequence:  %s', seqName)
        else:
            _log.warning('Ignored unknown sequence %s', seqName)
    return doSave


def mergeConfig(path, config, option):
    """Merge selected values from option into config."""
    importFilename = os.path.realpath(option)
    cfgFilename = os.path.join(path, config)
    if os.path.samefile(cfgFilename, importFilename):
        _log.warning('Ignored import from existing config')
        return
    if os.path.exists(importFilename):
        _log.info('Importing config from %r', importFilename)
        try:
            importConf = None
            with open(importFilename) as f:
                importConf = json.load(f)
            cfgConf = None
            with open(cfgFilename) as f:
                cfgConf = json.load(f)
            if mergeCfg(importConf, cfgConf):
                _log.info('Saving updated config')
                tmpName = None
                if os.path.exists(cfgFilename):
                    tmpName = cfgFilename + token_hex(6)
                    os.link(cfgFilename, tmpName)
                with SaveFile(cfgFilename) as f:
                    json.dump(cfgConf, f, indent=1)
                if tmpName is not None:
                    os.rename(tmpName, cfgFilename + '.bak')
            else:
                _log.warning('No updates imported')

        except Exception as e:
            _log.warning('Ignored invalid import, %s: %s',
                         e.__class__.__name__, e)
    else:
        _log.warning('Import file not found, ignored')


def initSite(path, webUi=True, webPort=None):
    """Prepare a new empty site under path, returns True to continue"""
    cfgPath = os.path.realpath(path)
    cfgFile = os.path.join(cfgPath, defaults.CONFIGPATH)
    backup = False

    # check for an existing config
    if os.path.exists(cfgFile):
        choice = None
        if sys.stdin.isatty():
            prompt = 'Replace existing site? (y/N) '
            choice = input(prompt)
        if not choice or choice.lower()[0] != 'y':
            _log.error('Existing site not overwritten')
            return False

    # create initial configuration
    siteCfg = {}
    siteCfg['base'] = cfgPath
    siteCfg['timezone'] = defaults.TIMEZONE
    if webUi:
        siteCfg['webui'] = dict(defaults.WEBUICONFIG)
        if webPort is not None:
            siteCfg['webui']['por'] = max(min(webPort, 65535), 1)
        else:
            siteCfg['webui']['port'] = 30000 + randbits(15)
        mkCert(cfgPath, siteCfg['webui']['hostname'])
        siteCfg['webui']['cert'] = os.path.join(cfgPath, defaults.SSLCERT)
        siteCfg['webui']['key'] = os.path.join(cfgPath, defaults.SSLKEY)

        # create admin user
        siteCfg['webui']['users'] = {}
        adminPw = randPass()
        siteCfg['webui']['users'][defaults.ADMINUSER] = createHash(adminPw)
        # add dummy hash for unknown users
        siteCfg['webui']['users'][''] = createHash(randPass())
    else:
        siteCfg['webui'] = None

    # Add an empty set of checks
    siteCfg['checks'] = {}

    # saveconfig
    tmpName = None
    if os.path.exists(cfgFile):
        tmpName = cfgFile + token_hex(6)
        os.link(cfgFile, tmpName)
    with SaveFile(cfgFile) as f:
        json.dump(siteCfg, f, indent=1)
    if tmpName is not None:
        os.rename(tmpName, cfgFile + '.bak')

    # report
    if webUi:
        print(
            '\nSite address:\thttps://%s:%d\nAdmin password:\t%s\n' %
            (siteCfg['webui']['hostname'], siteCfg['webui']['port'], adminPw))
    else:
        print('\nConfigured without web interface.\n')
    if sys.stdin.isatty():
        choice = input('Start? (Y/n) ')
        if choice and choice.lower()[0] == 'n':
            return False
        else:
            return True
    return False


def updateCheck(site, oldName, newName, config):
    """Update an existing check on a running site"""
    # un-schedule
    job = site.scheduler.get_job(oldName)
    if job is not None:
        _log.debug('Removing %s (%r) from schedule', oldName, job)
        site.scheduler.remove_job(oldName)

    # fetch handle to old check and remove from site
    oldCheck = site.checks[oldName]
    del site.checks[oldName]

    # add updated config to site with new name
    addCheck(site, newName, config, update=True)

    # repair dependencies and sequences
    newCheck = site.checks[newName]
    for name in site.checks:
        if name != newName:
            c = site.checks[name]
            c.replace_depend(oldName, newCheck)
            if c.checkType == 'sequence':
                c.replace_check(oldName, newCheck)
            if oldName != newName:
                if 'checks' in c.options:
                    if isinstance(c.options['checks'], list):
                        cl = c.options['checks']
                        if oldName in cl:
                            cl[cl.index(oldName)] = newName
    # refresh site map
    site.checkMap(True)


def addAction(site, name, config):
    nAct = loadAction(name, config)
    if nAct is not None:
        site.actions[name] = nAct
        _log.warning('Added action %s to site', name)


def addCheck(site, name, config, update=False):
    """Add the named check to running site, or replace existing if update set"""
    newCheck = loadCheck(name, config, site.timezone)

    # add actions to check
    if 'actions' in config:
        if isinstance(config['actions'], list):
            for a in config['actions']:
                if a in site.actions:
                    newCheck.add_action(site.actions[a])
                else:
                    _log.info('%s ignored unknown action %s', name, a)

    # update check dependencies
    if 'depends' in config:
        if isinstance(config['depends'], list):
            for d in config['depends']:
                if d in site.checks:
                    newCheck.add_depend(site.checks[d])

    # update sequence checks
    if newCheck.checkType == 'sequence':
        if 'checks' in newCheck.options:
            if isinstance(newCheck.options['checks'], list):
                for subName in newCheck.options['checks']:
                    if subName in site.checks:
                        newCheck.add_check(site.checks[subName])

    # add check to site
    site.checks[name] = newCheck
    if newCheck.remoteId is not None:
        site.remotes[newCheck.remoteId] = name
    _log.debug('Load check %r (%s)', name, newCheck.checkType)

    # schedule check
    if newCheck.trigger is not None:
        trigOpts = None
        trigType = None
        if 'interval' in newCheck.trigger:
            trigType = 'interval'
            trigOpts = dict(newCheck.trigger['interval'])
            # set first trigger to run shortly after adding
            trigOpts['start_date'] = datetime.now(UTC) + timedelta(
                seconds=defaults.FIRSTTRIGGER)
        elif 'cron' in newCheck.trigger:
            trigType = 'cron'
            trigOpts = dict(newCheck.trigger['cron'])
        if trigType is not None:
            _log.debug('Adding %s %s trigger to schedule: %r', name, trigType,
                       trigOpts)
            if 'timezone' not in trigOpts:
                if newCheck.timezone:
                    trigOpts['timezone'] = newCheck.timezone
                elif site.timezone:
                    trigOpts['timezone'] = site.timezone
            trigOpts['jitter'] = defaults.TRIGGERJITTER
            site.scheduler.add_job(site.runCheck,
                                   trigger=trigType,
                                   kwargs={'name': name},
                                   id=name,
                                   **trigOpts)
    if not update:
        # refresh site map
        site.checkMap(True)
        _log.warning('Added check %s (%s) to site', name, newCheck.checkType)
    else:
        _log.warning('Updated check %s (%s)', name, newCheck.checkType)


def deleteAction(site, actionName):
    """Remove action from running site"""
    for checkName in site.checks:
        site.checks[checkName].del_action(actionName)
    del site.actions[actionName]
    _log.warning('Deleted action %s', actionName)


def updateUser(site, username, password=None, passHash=None):
    """Update or add user"""
    if site.webCfg is not None:
        if username:
            if password or passHash:
                if passHash is None:
                    passHash = createHash(password)
                site.webCfg['users'][username] = passHash
                _log.warning('Updated user %s', username)


def deleteUser(site, username):
    """Remove username from webui"""
    if site.webCfg is not None:
        if username and username != defaults.ADMINUSER:
            if username in site.webCfg['users']:
                del site.webCfg['users'][username]
                _log.warning('Deleted user %s', username)


def deleteCheck(site, checkName):
    """Remove check from running site"""
    # un-schedule
    job = site.scheduler.get_job(checkName)
    if job is not None:
        _log.debug('Removing %s (%r) from schedule', checkName, job)
        site.scheduler.remove_job(checkName)

    # remove
    if checkName in site.checks:
        tempCheck = site.checks[checkName]
        if tempCheck.remoteId is not None:
            del site.remotes[tempCheck.remoteId]
        del site.checks[checkName]

        # remove check from depends and sequences
        for name in site.checks:
            c = site.checks[name]
            c.del_depend(checkName)
            if c.checkType == 'sequence':
                c.del_check(checkName)

        topic = None
        if checkName in site.remoteTopics:
            topic = site.remoteTopics[checkName]
            _log.debug('Clear retain for remote check %s->%s', checkName,
                       topic)
            site.clearMsg(topic=topic)
            del site.remoteTopics[checkName]
        if tempCheck.publish:
            if tempCheck.publish != topic:
                _log.debug('Clear retain for check with publish %s->%s',
                           checkName, tempCheck.publish)
                site.clearMsg(topic=tempCheck.publish)

    # refresh site map
    site.checkMap(True)
    _log.warning('Deleted check %s from site', checkName)


def reorderSite(site, checkName, mode):
    """Reorder check in site as per mode, return True if changes made."""
    target = site.checks[checkName]
    siteMap = site.checkMap()
    if mode == 'dep':
        reMap = False
        if target.checkType != 'sequence':
            # Find first sequence this check belongs to and then check deps
            for seqName in siteMap:
                if checkName in siteMap[seqName]:
                    maxPri = -1
                    for dep in target.depends:
                        if dep in siteMap[seqName]:
                            maxPri = max(target.depends[dep].priority, maxPri)
                    if target.priority <= maxPri:
                        _log.debug('Adjusted priority on %s %d->%d', checkName,
                                   target.priority, maxPri + 1)
                        target.priority = maxPri + 1
                        reMap = True
                    break
        if reMap:
            siteMap = site.checkMap(True)

    if target.checkType == 'sequence':
        _log.debug('Re-order sequence check %r: %r', checkName, mode)
        if len(siteMap) < 3:
            _log.debug('Ignored request to reorder less than 2 sequences')
            return False
        else:
            seqOrd = [s for s in siteMap]
            seqOrd.remove(None)
            seqIdx = seqOrd.index(checkName)
            newIdx = seqIdx
            if mode == 'up':
                if seqIdx == 0:
                    _log.debug('Sequence already first')
                    return False
                newIdx -= 1
            elif mode == 'down':
                if seqIdx >= (len(seqOrd) - 1):
                    _log.debug('Sequence already last')
                    return False
                newIdx += 1
            elif mode == 'dep':
                pass

            # swap elements
            temp = seqOrd[seqIdx]
            seqOrd[seqIdx] = seqOrd[newIdx]
            seqOrd[newIdx] = temp

            # re-assign sequence priorities without changing subchecks
            priority = 100
            for seqName in seqOrd:
                site.checks[seqName].priority = priority
                priority += 100

            # force re-calculation of site map
            site.checkMap(True)
            return True
    else:
        _log.debug('Re-order check %r: %r', checkName, mode)
        # find first occurrence of check in map
        for seqName in siteMap:
            if checkName in siteMap[seqName]:
                seqStart = 10000
                if seqName is not None:
                    seqStart = site.checks[seqName].priority
                seqOrd = [c for c in siteMap[seqName]]
                if len(seqOrd) < 2:
                    _log.debug('Ignored request to reorder single check')
                    return False
                seqIdx = seqOrd.index(checkName)
                newIdx = seqIdx
                if mode == 'up':
                    if seqIdx == 0:
                        _log.debug('Check already first in sequence')
                        return False
                    newIdx -= 1
                elif mode == 'down':
                    if seqIdx >= (len(seqOrd) - 1):
                        _log.debug('Check already last in sequence')
                        return False
                    newIdx += 1
                elif mode == 'dep':
                    pass

                # swap elements
                temp = seqOrd[seqIdx]
                seqOrd[seqIdx] = seqOrd[newIdx]
                seqOrd[newIdx] = temp

                # re-assign sequence priorities without changing subchecks
                for checkName in seqOrd:
                    seqStart += 2  # Allow space for a dependent
                    site.checks[checkName].priority = seqStart

                # force re-calculation of site map
                site.checkMap(True)
                return True
    return False


def loadSite(site):
    """Load and initialise site"""
    cfg = None
    try:
        srcCfg = None
        with open(site.configFile) as f:
            srcCfg = json.load(f)

        if 'base' in srcCfg and isinstance(srcCfg['base'], str):
            site.base = srcCfg['base']

        if 'timezone' in srcCfg and isinstance(srcCfg['timezone'], str):
            site.timezone = getZone(srcCfg['timezone'])

        if 'webui' in srcCfg and isinstance(srcCfg['webui'], dict):
            site.webCfg = {}
            for k in defaults.WEBUICONFIG:
                if k in srcCfg['webui']:
                    site.webCfg[k] = srcCfg['webui'][k]
                else:
                    site.webCfg[k] = defaults.WEBUICONFIG[k]

        if 'mqtt' in srcCfg and isinstance(srcCfg['mqtt'], dict):
            site.mqttCfg = {}
            for k in defaults.MQTTCONFIG:
                if k in srcCfg['mqtt']:
                    site.mqttCfg[k] = srcCfg['mqtt'][k]
                else:
                    site.mqttCfg[k] = defaults.MQTTCONFIG[k]

        if 'log' in srcCfg and isinstance(srcCfg['log'], list):
            site.log = srcCfg['log']

        scheduler = AsyncIOScheduler()

        # load actions
        site.actions = {}
        if 'actions' in srcCfg and isinstance(srcCfg['actions'], dict):
            for a in srcCfg['actions']:
                nAct = loadAction(a, srcCfg['actions'][a])
                if nAct is not None:
                    site.actions[a] = nAct
                    _log.debug('Load action %r (%s)', a, nAct.actionType)

        # load checks
        site.checks = {}
        site.remotes = {}
        if 'checks' in srcCfg and isinstance(srcCfg['checks'], dict):
            for c in srcCfg['checks']:
                if isinstance(srcCfg['checks'][c], dict):
                    newCheck = loadCheck(c, srcCfg['checks'][c], site.timezone)
                    # add actions
                    if 'actions' in srcCfg['checks'][c]:
                        if isinstance(srcCfg['checks'][c]['actions'], list):
                            for a in srcCfg['checks'][c]['actions']:
                                if a in site.actions:
                                    newCheck.add_action(site.actions[a])
                                else:
                                    _log.info('%s ignored unknown action %s',
                                              c, a)
                    site.checks[c] = newCheck
                    if newCheck.remoteId is not None:
                        site.remotes[newCheck.remoteId] = c
                    _log.debug('Load check %r (%s)', c, newCheck.checkType)
        # patch the check dependencies, sequences and triggers
        for c in site.checks:
            if c in srcCfg['checks'] and 'depends' in srcCfg['checks'][c]:
                if isinstance(srcCfg['checks'][c]['depends'], list):
                    for d in srcCfg['checks'][c]['depends']:
                        if d in site.checks:
                            site.checks[c].add_depend(site.checks[d])
            if site.checks[c].checkType == 'sequence':
                if 'checks' in site.checks[c].options:
                    if isinstance(site.checks[c].options['checks'], list):
                        for s in site.checks[c].options['checks']:
                            if s in site.checks:
                                site.checks[c].add_check(site.checks[s])
            if site.checks[c].trigger is not None:
                trigOpts = None
                trigType = None
                if 'interval' in site.checks[c].trigger:
                    if isinstance(site.checks[c].trigger['interval'], dict):
                        trigOpts = dict(site.checks[c].trigger['interval'])
                        # set first trigger to run shortly after adding
                        trigOpts['start_date'] = datetime.now(UTC) + timedelta(
                            seconds=defaults.FIRSTTRIGGER)
                    trigType = 'interval'
                elif 'cron' in site.checks[c].trigger:
                    if isinstance(site.checks[c].trigger['cron'], dict):
                        trigOpts = dict(site.checks[c].trigger['cron'])
                    trigType = 'cron'
                if trigType is not None:
                    _log.debug('Adding %s trigger to check %s: %r', trigType,
                               c, trigOpts)
                    if 'timezone' not in trigOpts:
                        if site.checks[c].timezone:
                            trigOpts['timezone'] = site.checks[c].timezone
                        elif site.timezone:
                            trigOpts['timezone'] = site.timezone
                    trigOpts['jitter'] = defaults.TRIGGERJITTER
                    scheduler.add_job(site.runCheck,
                                      trigger=trigType,
                                      misfire_grace_time=None,
                                      kwargs={'name': c},
                                      id=c,
                                      **trigOpts)
                else:
                    _log.info('Invalid trigger for %s ignored', c)
                    site.checks[c].trigger = None

        site.scheduler = scheduler
        site.scheduler.start()
        # refresh site map
        site.checkMap(True)
    except Exception as e:
        _log.error('%s reading config: %s', e.__class__.__name__, e)


def mkCert(path, hostname):
    """Call openssl to make a self-signed certificate for hostname"""
    # Consider removal or replacement
    _log.debug('Creating self-signed SSL cert for %r at %r', hostname, path)
    crtTmp = None
    with NamedTemporaryFile(mode='w',
                            suffix='.tmp',
                            prefix='sav_',
                            dir=path,
                            delete=False) as f:
        crtTmp = f.name
    keyTmp = None
    with NamedTemporaryFile(mode='w',
                            suffix='.tmp',
                            prefix='sav_',
                            dir=path,
                            delete=False) as f:
        keyTmp = f.name
    crtOut = os.path.join(path, defaults.SSLCERT)
    keyOut = os.path.join(path, defaults.SSLKEY)
    template = """
[dn]
CN=%s
[req]
distinguished_name = dn
[EXT]
subjectAltName=DNS:%s
keyUsage=digitalSignature
extendedKeyUsage=serverAuth""" % (hostname, hostname)
    subject = '/CN=%s' % (hostname)
    cmd = [
        'openssl', 'req', '-x509', '-out', crtTmp, '-keyout', keyTmp,
        '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', subject,
        '-extensions', 'EXT', '-config', '-'
    ]
    try:
        ret = run(cmd, input=template.encode('utf-8'), capture_output=True)
        if ret.returncode != 0:
            _log.error('Error creating SSL certificate: %s', ret.stderr)
        _log.debug('SSL certificate created OK')
        os.rename(crtTmp, crtOut)
        os.rename(keyTmp, keyOut)
    except Exception as e:
        _log.error('Error running openssl')
