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
from importlib.resources import files
from tornado.template import BaseLoader, Template
from tornado.web import StaticFileHandler, HTTPError
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


class PackageLoader(BaseLoader):
    """Tornado template loader for importlib.files"""

    def resolve_path(self, name, parent_path=None):
        return name

    def _create_template(self, name):
        template = None
        ref = files('fletchck.templates').joinpath(name)
        if ref.is_file():
            with ref.open(mode='rb') as f:
                template = Template(f.read(), name=name, loader=self)
        else:
            _log.error('Unable to find named resource %s in templates', name)
        return template


class PackageFileHandler(StaticFileHandler):
    """Tornado static file handler for importlib.files"""

    @classmethod
    def get_absolute_path(cls, root, path):
        """Return the absolute path from importlib"""
        absolute_path = files('fletchck.static').joinpath(path)
        return absolute_path

    def validate_absolute_path(self, root, absolute_path):
        """Validate and return the absolute path"""
        if not absolute_path.is_file():
            raise HTTPError(404)
        return absolute_path

    @classmethod
    def get_content(cls, abspath, start=None, end=None):
        with abspath.open('rb') as file:
            if start is not None:
                file.seek(start)
            if end is not None:
                remaining = end - (start or 0)
            else:
                remaining = None
            while True:
                chunk_size = 64 * 1024
                if remaining is not None and remaining < chunk_size:
                    chunk_size = remaining
                chunk = file.read(chunk_size)
                if chunk:
                    if remaining is not None:
                        remaining -= len(chunk)
                    yield chunk
                else:
                    if remaining is not None:
                        assert remaining == 0
                    return

    def set_default_headers(self, *args, **kwargs):
        self.set_header("Content-Security-Policy",
                        "frame-ancestors 'none'; default-src 'self'")
        self.set_header("Strict-Transport-Security", "max-age=31536000")
        self.set_header("X-Frame-Options", "deny")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Permitted-Cross-Domain-Policies", "none")
        self.set_header("Referrer-Policy", "no-referrer")
        self.set_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.set_header("Cross-Origin-Opener-Policy", "same-origin")
        self.set_header("Cross-Origin-Resource-Policy", "same-origin")
        self.clear_header("Server")


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


def saveSite(siteCfg, cfgFile):
    """Save the current site state to disk"""
    dstCfg = {'base': None, 'webui': None}
    if 'base' in siteCfg and isinstance(siteCfg['base'], str):
        dstCfg['base'] = siteCfg['base']
    if 'webui' in siteCfg and siteCfg['webui'] is not None:
        dstCfg['webui'] = {}
        for k in defaults.WEBUICONFIG:
            dstCfg['webui'][k] = siteCfg['webui'][k]
    dstCfg['actions'] = {}
    for a in siteCfg['actions']:
        dstCfg['actions'][a] = siteCfg['actions'][a].flatten()
    dstCfg['checks'] = {}
    for c in siteCfg['checks']:
        dstCfg['checks'][c] = siteCfg['checks'][c].flatten()

    # backup existing config and save
    tmpName = None
    if os.path.exists(cfgFile):
        tmpName = cfgFile + token_hex(6)
        os.link(cfgFile, tmpName)
    with SaveFile(cfgFile) as f:
        json.dump(dstCfg, f, indent=1)
    if tmpName is not None:
        os.rename(tmpName, cfgFile + '.bak')


def initSite(path):
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
    siteCfg['webui'] = dict(defaults.WEBUICONFIG)
    siteCfg['webui']['port'] = 30000 + randbits(15)
    mkCert(cfgPath, siteCfg['webui']['host'])
    siteCfg['webui']['cert'] = os.path.join(cfgPath, 'cert')
    siteCfg['webui']['key'] = os.path.join(cfgPath, 'key')
    siteCfg['actions'] = {}
    siteCfg['checks'] = {}

    # create admin user
    siteCfg['webui']['users'] = {}
    adminPw = randPass()
    siteCfg['webui']['users']['admin'] = createHash(adminPw)
    # add dummy hash for unknown users
    siteCfg['webui']['users'][''] = createHash(randPass())

    # saveconfig
    saveSite(siteCfg, cfgFile)

    # report
    print('\nSite address:\thttps://%s:%d/\nAdmin password:\t%s\n' %
          (siteCfg['webui']['host'], siteCfg['webui']['port'], adminPw))
    choice = input('Start? (Y/n) ')
    if choice and choice.lower()[0] == 'n':
        return False
    return True


def loadSite(cfgFile=None):
    """Load and initialise site"""
    cfg = None
    try:
        srcCfg = None
        with open(cfgFile) as f:
            srcCfg = json.load(f)
        dstCfg = {'base': None, 'webui': None}
        if 'base' in srcCfg and isinstance(srcCfg['base'], str):
            dstCfg['base'] = srcCfg['base']
        if 'webui' in srcCfg and isinstance(srcCfg['webui'], dict):
            dstCfg['webui'] = {}
            for k in defaults.WEBUICONFIG:
                if k in srcCfg['webui']:
                    # todo - properly check input
                    dstCfg['webui'][k] = srcCfg['webui'][k]
                else:
                    dstCfg['webui'][k] = defaults.WEBUICONFIG[k]
        dstCfg['scheduler'] = AsyncIOScheduler()
        dstCfg['scheduler'].start()

        # load actions
        dstCfg['actions'] = {}
        if 'actions' in srcCfg and isinstance(srcCfg['actions'], dict):
            for a in srcCfg['actions']:
                nAct = action.loadAction(a, srcCfg['actions'][a])
                if nAct is not None:
                    dstCfg['actions'][a] = nAct
                    _log.debug('Load action %r (%s)', a, nAct.actionType)

        # load checks
        dstCfg['checks'] = {}
        if 'checks' in srcCfg and isinstance(srcCfg['checks'], dict):
            for c in srcCfg['checks']:
                if isinstance(srcCfg['checks'][c], dict):
                    newCheck = check.loadCheck(c, srcCfg['checks'][c])
                    # add actions
                    if 'actions' in srcCfg['checks'][c]:
                        if isinstance(srcCfg['checks'][c]['actions'], list):
                            for a in srcCfg['checks'][c]['actions']:
                                if a in dstCfg['actions']:
                                    newCheck.add_action(dstCfg['actions'][a])
                                else:
                                    _log.info('%s ignored unknown action %s',
                                              c, a)
                    dstCfg['checks'][c] = newCheck
                    _log.debug('Load check %r (%s)', c, newCheck.checkType)
        # patch the check dependencies, sequences and triggers
        for c in dstCfg['checks']:
            if c in srcCfg['checks'] and 'depends' in srcCfg['checks'][c]:
                if isinstance(srcCfg['checks'][c]['depends'], list):
                    for d in srcCfg['checks'][c]['depends']:
                        if d in dstCfg['checks']:
                            dstCfg['checks'][c].add_depend(dstCfg['checks'][d])
            if dstCfg['checks'][c].checkType == 'sequence':
                if 'checks' in dstCfg['checks'][c].options:
                    if isinstance(dstCfg['checks'][c].options['checks'], list):
                        for s in dstCfg['checks'][c].options['checks']:
                            if s in dstCfg['checks']:
                                dstCfg['checks'][c].checks.append(
                                    dstCfg['checks'][s])
                                _log.debug('Adding %r to sequence %r', s, c)
            if dstCfg['checks'][c].trigger is not None:
                trigOpts = {}
                trigType = None
                if 'interval' in dstCfg['checks'][c].trigger:
                    if isinstance(dstCfg['checks'][c].trigger['interval'],
                                  dict):
                        trigOpts = dstCfg['checks'][c].trigger['interval']
                    trigType = 'interval'
                elif 'cron' in dstCfg['checks'][c].trigger:
                    if isinstance(dstCfg['checks'][c].trigger['cron'], dict):
                        trigOpts = dstCfg['checks'][c].trigger['cron']
                    trigType = 'cron'
                if trigType is not None:
                    _log.debug('Adding %s trigger to check %s: %r', trigType,
                               c, trigOpts)
                    dstCfg['scheduler'].add_job(dstCfg['checks'][c].update,
                                                trigType,
                                                id=c,
                                                **trigOpts)
                else:
                    _log.info('Invalid trigger for %s ignored', c)
                    dstCfg['checks'][c].trigger = None

        cfg = dstCfg
    except Exception as e:
        _log.error('%s reading config: %s', e.__class__.__name__, e)

    return cfg


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
    crtOut = os.path.join(path, 'cert')
    keyOut = os.path.join(path, 'key')
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
