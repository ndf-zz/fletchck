# SPDX-License-Identifier: MIT
"""Application support utilities"""

import os
import sys
import json
import struct
import math
from shutil import move, rmtree
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

_log = getLogger('util')
_log.setLevel(DEBUG)

if not rmtree.avoids_symlink_attacks:
    raise RuntimeError('rmtree not supported')


class savefile():
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
        ref = files('fletcher.templates').joinpath(name)
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
        absolute_path = files('fletcher.static').joinpath(path)
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


def initSite(path):
    """Prepare a new empty site under path, returns True to continue"""
    if not sys.stdin.isatty():
        _log.error('Init requires user input - exiting')
        return False

    # check for collision with source files
    realPath = os.path.realpath(path)
    srcPath = os.path.dirname(os.path.realpath(__file__))
    if os.path.samefile(realPath, srcPath):
        _log.error('Site path is program source')
        return False

    backup = False
    junkDir = None
    cfgPath = os.path.join(realPath, defaults.CONFIGPATH)

    # check for an existing config
    if os.path.exists(os.path.join(cfgPath, 'config')):
        prompt = 'Replace existing site? (y/N) '
        choice = input(prompt)
        if not choice or choice.lower()[0] != 'y':
            _log.error('Existing site not overwritten')
            return False

    # stash old config in junk dir
    print('Creating site under %s' % (realPath))
    if os.path.exists(cfgPath):
        junkDir = mkdtemp(dir=realPath)
        move(cfgPath, junkDir)
        backup = True
    os.mkdir(cfgPath, mode=0o700)

    # create initial configuration
    siteCfg = dict(defaults.CONFIG)
    siteCfg['base'] = realPath
    siteCfg['port'] = 30000 + randbits(15)
    mkCert(cfgPath, siteCfg['host'])
    siteCfg['cert'] = os.path.join(cfgPath, 'cert')
    siteCfg['key'] = os.path.join(cfgPath, 'key')

    # create admin user
    siteCfg['users'] = {}
    adminPw = randPass()
    siteCfg['users']['admin'] = createHash(adminPw)
    # add dummy hash for unknown users
    siteCfg['users'][''] = createHash(randPass())

    # write out config
    cfgFile = os.path.join(cfgPath, 'config')
    with savefile(cfgFile) as f:
        json.dump(siteCfg, f, indent=1)

    # check for old config
    if junkDir is not None:
        if backup:
            backup = False
            prompt = 'Retain old config files? (y/N) '
            choice = input(prompt)
            if choice and choice.lower()[0] == 'y':
                backup = True
        if not backup:
            rmtree(junkDir)
        else:
            print('Old config saved to %s' % (junkDir))

    # report
    print('\nSite address:\thttps://%s:%d/\nAdmin password:\t%s\n' %
          (siteCfg['host'], siteCfg['port'], adminPw))
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
        dstCfg = {}
        for k in defaults.CONFIG:
            if k in srcCfg:
                # todo - properly check input
                dstCfg[k] = srcCfg[k]
            else:
                dstCfg[k] = defaults.CONFIG[k]
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
        # patch the check dependencies
        for c in dstCfg['checks']:
            if c in srcCfg['checks'] and 'depends' in srcCfg['checks'][c]:
                if isinstance(srcCfg['checks'][c]['depends'], list):
                    for d in srcCfg['checks'][c]['depends']:
                        if d in dstCfg['checks']:
                            dstCfg['checks'][c].add_depend(dstCfg['checks'][d])

        # load schedule
        if 'schedule' in srcCfg and isinstance(srcCfg['schedule'], dict):
            for j in srcCfg['schedule']:
                refChk = None
                if 'check' in srcCfg['schedule'][j]:
                    if isinstance(srcCfg['schedule'][j]['check'], str):
                        if srcCfg['schedule'][j]['check'] in dstCfg['checks']:
                            refChkId = srcCfg['schedule'][j]['check']
                            refChk = dstCfg['checks'][refChkId]
                if refChk is not None:
                    trigOpts = {}
                    if 'trigger' in srcCfg['schedule'][j]:
                        # todo: sanitise trigger options for use with fletch`
                        if isinstance(srcCfg['schedule'][j]['trigger'], dict):
                            trigOpts = srcCfg['schedule'][j]['trigger']
                    dstCfg['scheduler'].add_job(refChk.update,
                                                'interval',
                                                id=j,
                                                **trigOpts)

        cfg = dstCfg
    except Exception as e:
        _log.error('%s reading config: %s', e.__class__.__name__, e)

    return cfg


def saveSite(siteCfg):
    """Save the current site state to disk"""
    _log.info('Save site - TODO')


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
