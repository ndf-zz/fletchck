# SPDX-License-Identifier: MIT
"""Application support utilities"""

import os
import sys
import json
import struct
import math
from secrets import randbits, token_hex
from passlib.hash import argon2 as kdf
from tempfile import NamedTemporaryFile, mkdtemp
from logging import getLogger, DEBUG, INFO, WARNING
from subprocess import run
from . import action
from . import check
from . import defaults
from apscheduler.schedulers.asyncio import AsyncIOScheduler

_log = getLogger('fletchck.util')
_log.setLevel(DEBUG)
getLogger('apscheduler.executors').setLevel(WARNING)
getLogger('apscheduler.executors.default').setLevel(WARNING)


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


def checkPass(pw, hash):
    return kdf.verify(pw, hash)


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
    dstCfg = {'base': site.base, 'webui': None}
    if site.webCfg is not None:
        dstCfg['webui'] = {}
        for k in defaults.WEBUICONFIG:
            dstCfg['webui'][k] = site.webCfg[k]
    dstCfg['actions'] = {}
    for a in site.actions:
        dstCfg['actions'][a] = site.actions[a].flatten()
    dstCfg['checks'] = {}
    for c in site.checks:
        dstCfg['checks'][c] = site.checks[c].flatten()

    # backup existing config and save
    tmpName = None
    if os.path.exists(site.configFile):
        tmpName = site.configFile + token_hex(6)
        os.link(site.configFile, tmpName)
    with SaveFile(site.configFile) as f:
        json.dump(dstCfg, f, indent=1)
    if tmpName is not None:
        os.rename(tmpName, site.configFile + '.bak')


def initSite(path, webUi=True):
    """Prepare a new empty site under path, returns True to continue"""
    if not sys.stdin.isatty():
        _log.error('Init requires user input - exiting')
        return False

    cfgPath = os.path.realpath(path)
    cfgFile = os.path.join(cfgPath, defaults.CONFIGPATH)
    backup = False

    # check for an existing config
    if os.path.exists(cfgFile):
        prompt = 'Replace existing site? (y/N) '
        choice = input(prompt)
        if not choice or choice.lower()[0] != 'y':
            _log.error('Existing site not overwritten')
            return False

    # create initial configuration
    siteCfg = {}
    siteCfg['base'] = cfgPath
    if webUi:
        siteCfg['webui'] = dict(defaults.WEBUICONFIG)
        siteCfg['webui']['port'] = 30000 + randbits(15)
        mkCert(cfgPath, siteCfg['webui']['hostname'])
        siteCfg['webui']['cert'] = os.path.join(cfgPath, defaults.SSLCERT)
        siteCfg['webui']['key'] = os.path.join(cfgPath, defaults.SSLKEY)
        siteCfg['actions'] = {}
        siteCfg['checks'] = {}

        # create admin user
        siteCfg['webui']['users'] = {}
        adminPw = randPass()
        siteCfg['webui']['users']['admin'] = createHash(adminPw)
        # add dummy hash for unknown users
        siteCfg['webui']['users'][''] = createHash(randPass())
    else:
        siteCfg['webui'] = None

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
    choice = input('Start? (Y/n) ')
    if choice and choice.lower()[0] == 'n':
        return False
    return True


def loadSite(site):
    """Load and initialise site"""
    cfg = None
    try:
        srcCfg = None
        with open(site.configFile) as f:
            srcCfg = json.load(f)

        if 'base' in srcCfg and isinstance(srcCfg['base'], str):
            site.base = srcCfg['base']

        if 'webui' in srcCfg and isinstance(srcCfg['webui'], dict):
            site.webCfg = {}
            for k in defaults.WEBUICONFIG:
                if k in srcCfg['webui']:
                    site.webCfg[k] = srcCfg['webui'][k]
                else:
                    site.webCfg[k] = defaults.WEBUICONFIG[k]

        scheduler = AsyncIOScheduler()

        # load actions
        site.actions = {}
        if 'actions' in srcCfg and isinstance(srcCfg['actions'], dict):
            for a in srcCfg['actions']:
                nAct = action.loadAction(a, srcCfg['actions'][a])
                if nAct is not None:
                    site.actions[a] = nAct
                    _log.debug('Load action %r (%s)', a, nAct.actionType)

        # load checks
        site.checks = {}
        if 'checks' in srcCfg and isinstance(srcCfg['checks'], dict):
            for c in srcCfg['checks']:
                if isinstance(srcCfg['checks'][c], dict):
                    newCheck = check.loadCheck(c, srcCfg['checks'][c])
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
                                site.checks[c].checks.append(site.checks[s])
                                _log.debug('Adding %r to sequence %r', s, c)
            if site.checks[c].trigger is not None:
                trigOpts = {}
                trigType = None
                if 'interval' in site.checks[c].trigger:
                    if isinstance(site.checks[c].trigger['interval'], dict):
                        trigOpts = site.checks[c].trigger['interval']
                    trigType = 'interval'
                elif 'cron' in site.checks[c].trigger:
                    if isinstance(site.checks[c].trigger['cron'], dict):
                        trigOpts = site.checks[c].trigger['cron']
                    trigType = 'cron'
                if trigType is not None:
                    _log.debug('Adding %s trigger to check %s: %r', trigType,
                               c, trigOpts)
                    scheduler.add_job(site.checks[c].update,
                                      trigType,
                                      id=c,
                                      **trigOpts)
                else:
                    _log.info('Invalid trigger for %s ignored', c)
                    site.checks[c].trigger = None

        site.scheduler = scheduler
        site.scheduler.start()
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
