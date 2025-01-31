# SPDX-License-Identifier: MIT
"""Fletchck Web Interface"""

import asyncio
import ssl
import tornado.web
import tornado.ioloop
import tornado.template
import json
import os
from importlib.resources import files
from . import defaults
from . import util
from logging import getLogger, DEBUG, INFO, WARNING

_log = getLogger('fletchck.webui')
_log.setLevel(DEBUG)


class PackageLoader(tornado.template.BaseLoader):
    """Tornado template loader for importlib.files"""

    def resolve_path(self, name, parent_path=None):
        return name

    def _create_template(self, name):
        template = None
        ref = files('fletchck.templates').joinpath(name)
        if ref.is_file():
            with ref.open(mode='rb') as f:
                template = tornado.template.Template(f.read(),
                                                     name=name,
                                                     loader=self)
        else:
            _log.error('Unable to find named resource %s in templates', name)
        return template


class PackageFileHandler(tornado.web.StaticFileHandler):
    """Tornado static file handler for importlib.files"""

    @classmethod
    def get_absolute_path(cls, root, path):
        """Return the absolute path from importlib"""
        absolute_path = files('fletchck.static').joinpath(path)
        return absolute_path

    def validate_absolute_path(self, root, absolute_path):
        """Validate and return the absolute path"""
        if not absolute_path.is_file():
            raise tornado.web.HTTPError(404)
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
        self.set_header("Content-Security-Policy", defaults.CSP)
        self.set_header("Strict-Transport-Security", "max-age=31536000")
        self.set_header("X-Frame-Options", "deny")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Permitted-Cross-Domain-Policies", "none")
        self.set_header("Referrer-Policy", "no-referrer")
        self.set_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.set_header("Cross-Origin-Opener-Policy", "same-origin")
        self.set_header("Cross-Origin-Resource-Policy", "same-origin")
        self.clear_header("Server")


class Application(tornado.web.Application):

    def __init__(self, site):
        handlers = [
            (r"/", HomeHandler, dict(site=site)),
            (r"/checks", ChecksHandler, dict(site=site)),
            (r"/check/(.*)", CheckHandler, dict(site=site)),
            (r"/move/(.*)", MoveHandler, dict(site=site)),
            (r"/clone/(.*)", CloneHandler, dict(site=site)),
            (r"/config", ConfigHandler, dict(site=site)),
            (r"/action/(.*)", ActionHandler, dict(site=site)),
            (r"/user/(.*)", UserHandler, dict(site=site)),
            (r"/login", AuthLoginHandler, dict(site=site)),
            (r"/log", LogHandler, dict(site=site)),
            (r"/status", StatusHandler, dict(site=site)),
            (r"/logout", AuthLogoutHandler, dict(site=site)),
        ]
        templateLoader = PackageLoader(whitespace='oneline')
        settings = dict(
            site_version=defaults.VERSION,
            site_name=site.webCfg['name'],
            autoreload=False,
            serve_traceback=False,
            static_path='static',
            static_url_prefix='/s/',
            static_handler_class=PackageFileHandler,
            template_loader=templateLoader,
            cookie_secret=util.token_hex(32),
            login_url='/login?',
            debug=False,
        )
        super().__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):

    def initialize(self, site):
        self._site = site

    def get_current_user(self):
        username = None
        cookie = self.get_signed_cookie("user",
                                        max_age_days=defaults.AUTHEXPIRY)
        if cookie is not None:
            username = cookie.decode('utf-8', 'replace')
            # invalidate sessions for a deleted user
            if username not in self._site.webCfg['users']:
                _log.warning('Rejected invalid session for deleted user: %s',
                             username)
                username = None
        return username

    def set_default_headers(self, *args, **kwargs):
        self.set_header("Content-Security-Policy", defaults.CSP)
        self.set_header("Strict-Transport-Security", "max-age=31536000")
        self.set_header("X-Frame-Options", "deny")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Permitted-Cross-Domain-Policies", "none")
        self.set_header("Referrer-Policy", "no-referrer")
        self.set_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.set_header("Cross-Origin-Opener-Policy", "same-origin")
        self.set_header("Cross-Origin-Resource-Policy", "same-origin")
        self.clear_header("Server")


class HomeHandler(BaseHandler):
    """Site landing page."""

    @tornado.web.authenticated
    async def get(self):
        status = self._site.getStatus()
        self.render("home.html",
                    site=self._site,
                    status=status,
                    section='home')


class LogHandler(BaseHandler):
    """View of site logs."""

    @tornado.web.authenticated
    async def get(self):
        if self.get_argument('clear', ''):
            _log.info('Clearing volatile log')
            self._site.log.clear()
        status = self._site.getStatus()
        self.render("log.html", site=self._site, status=status, section='log')


class ChecksHandler(BaseHandler):
    """List of defined checks."""

    @tornado.web.authenticated
    async def get(self):
        status = self._site.getStatus()
        self.render("checks.html",
                    site=self._site,
                    status=status,
                    section='check')


class CloneHandler(BaseHandler):
    """Check cloning handler."""

    @tornado.web.authenticated
    async def get(self, path):
        check = None
        if path:
            if path in self._site.checks:
                status = self._site.getStatus()
                doSave = False
                checkName = path
                check = self._site.checks[checkName]
                newName = self._site.copyName(checkName)
                if check.checkType == 'remote':
                    _log.info('Unable to clone remote check %s', checkName)
                elif check.checkType == 'sequence':
                    _log.debug('Cloning sequence %s to %s', checkName, newName)
                    map = self._site.checkMap()
                    newConf = check.flatten()
                    del (newConf['data'])
                    oldChecks = []
                    if 'checks' in newConf['options']:
                        if newConf['options']['checks']:
                            oldChecks = newConf['options']['checks']
                            del (newConf['options']['checks'])

                    # determine and record clone sub check names
                    oldNew = {}
                    newChecks = []
                    for oldSubName in oldChecks:
                        if oldSubName in self._site.checks:
                            oldSubCheck = self._site.checks[oldSubName]
                            if oldSubCheck.checkType != 'remote':
                                newSubName = self._site.copyName(oldSubName)
                                oldNew[oldSubName] = newSubName
                                newChecks.append(newSubName)
                            else:
                                _log.debug(
                                    'Omitting remote check %s from clone',
                                    oldSubName)
                    newConf['options']['checks'] = newChecks

                    # create the cloned subchecks
                    for oldSubName in oldNew:
                        newSubName = oldNew[oldSubName]
                        _log.debug('Adding new subcheck: %s clone of %s',
                                   newSubName, oldSubName)
                        subCheck = self._site.checks[oldSubName]
                        newSubConf = subCheck.flatten()
                        del (newSubConf['data'])
                        newDeps = []
                        for depName in newSubConf['depends']:
                            if depName:
                                if depName in oldNew:
                                    newDeps.append(oldNew[depName])
                                else:
                                    newDeps.append(depName)
                        newSubConf['depends'] = newDeps
                        util.addCheck(self._site, newSubName, newSubConf)

                    # add sequence
                    util.addCheck(self._site, newName, newConf)
                    self._site.checkMap(True)
                    doSave = True
                else:
                    _log.debug('Cloning check %s to %s', checkName, newName)
                    newConf = check.flatten()
                    del (newConf['data'])
                    util.addCheck(self._site, newName, newConf)
                    if newName in self._site.checks:
                        newCheck = self._site.checks[newName]
                        if checkName in status['inseqs']:
                            for seqName in status['inseqs'][checkName]:
                                if seqName in self._site.checks:
                                    _log.debug(
                                        'Adding clone check %s to sequence %s',
                                        newName, seqName)
                                    seq = self._site.checks[seqName]
                                    seq.add_check(newCheck)
                            self._site.checkMap(True)
                    else:
                        _log.error('New check %s not yet on site', newName)
                    doSave = True
                if doSave:
                    await tornado.ioloop.IOLoop.current().run_in_executor(
                        None, self._site.saveConfig)

                self.redirect('/checks')
                return
            else:
                raise tornado.web.HTTPError(404)
        self.redirect('/checks')
        return


class MoveHandler(BaseHandler):
    """Check reordering handler."""

    @tornado.web.authenticated
    async def get(self, path):
        check = None
        if path:
            if path in self._site.checks:
                checkName = path
                mode = self.get_argument('m', 'down')
                if mode in ('down', 'up'):
                    if util.reorderSite(self._site, checkName, mode):
                        # save out config
                        await tornado.ioloop.IOLoop.current().run_in_executor(
                            None, self._site.saveConfig)
                else:
                    _log.warning('Ignored invalid mode mode')
                self.redirect('/checks')
                return
            else:
                raise tornado.web.HTTPError(404)
        self.redirect('/checks')
        return


class UserHandler(BaseHandler):
    """User editor."""

    @tornado.web.authenticated
    async def get(self, path):
        if self.current_user != defaults.ADMINUSER:
            _log.warning('User %s not authorised to edit users',
                         self.current_user)
            raise tornado.web.HTTPError(403)
        tmpPass = ''
        curUser = ''
        if path:
            if path in self._site.webCfg['users']:
                curUser = path
                if self.get_argument('delete', ''):
                    if curUser == defaults.ADMINUSER:
                        _log.warning('Administrator %s may not be deleted',
                                     defaults.ADMINUSER)
                        raise tornado.web.HTTPError(403)

                    _log.debug('Deleting user %s without undo', curUser)
                    self._site.deleteUser(curUser)
                    self.redirect('/config')
                    return
            else:
                raise tornado.web.HTTPError(404)
        else:
            # new user creation path
            tmpPass = util.randPass()
        status = self._site.getStatus()
        self.render("user.html",
                    status=status,
                    oldName=path,
                    user=curUser,
                    tmpPass=tmpPass,
                    section='config',
                    site=self._site,
                    adminuser=path == defaults.ADMINUSER,
                    formErrors=None)
        return

    @tornado.web.authenticated
    async def post(self, path):
        formErrors = []
        if self.current_user != defaults.ADMINUSER:
            _log.warning('User %s not authorised to edit users',
                         self.current_user)
            raise tornado.web.HTTPError(403)
        if path:
            if path in self._site.webCfg['users']:
                oldName = path
            else:
                raise tornado.web.HTTPError(404)
        oldName = self.get_argument('oldName', None)
        if oldName != path:
            _log.error('Form error: oldName does not match path request')
            raise tornado.web.HTTPError(500)
        newName = self.get_argument('username', '')
        if newName:
            if newName != oldName:
                if newName in self._site.webCfg['users']:
                    formErrors.append(
                        'Invalid username, please choose another')
            else:
                if oldName == defaults.ADMINUSER:
                    _log.error('Form error: Reject username change for admin')
                    raise tornado.web.HTTPError(500)
        else:
            if oldName == defaults.ADMINUSER:
                newName = oldName
            else:
                formErrors.append('Username required')

        newPass = self.get_argument('password', '')
        oldHash = None
        if not newPass:
            if path:
                oldHash = self._site.webCfg['users'][oldName]
            else:
                formErrors.append('Password required for new user')

        if formErrors:
            _log.info('User update %s with form errors', path)
            status = self._site.getStatus()
            self.render("user.html",
                        status=status,
                        oldName=path,
                        user=newName,
                        tmpPass=newPass,
                        section='config',
                        site=self._site,
                        adminuser=path == defaults.ADMINUSER,
                        formErrors=formErrors)
            return

        if newName != oldName:
            self._site.deleteUser(oldName)
        if newName != oldName or newPass:
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.updateUser, newName, newPass, oldHash)
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.saveConfig)
        else:
            _log.debug('No change required on user %s', oldName)
        self.redirect('/config')


class ActionHandler(BaseHandler):
    """Action editor."""

    @tornado.web.authenticated
    async def get(self, path):
        testMsg = None
        curAction = None
        if path:
            if path in self._site.actions:
                curAction = self._site.actions[path]
                runopt = self.get_argument('run', '')
                if self.get_argument('delete', ''):
                    _log.info('Deleting action %s without undo', path)
                    self._site.deleteAction(path)
                    self.redirect('/config')
                    return
                elif runopt:
                    _log.info('Manually running action %s', path)
                    res = await tornado.ioloop.IOLoop.current(
                    ).run_in_executor(None, self._site.testAction, path)
                    if res:
                        testMsg = 'Action test completed without error.'
                    else:
                        testMsg = 'Action test failed, check log for details.'

                    if runopt == 'list':
                        self.redirect('/config')
                        return
            else:
                raise tornado.web.HTTPError(404)
        else:
            curAction = util.loadAction(name='', config={'type': 'email'})
        status = self._site.getStatus()
        self.render("action.html",
                    status=status,
                    oldName=path,
                    curAction=curAction,
                    section='config',
                    site=self._site,
                    testMsg=testMsg,
                    formErrors=None)

    @tornado.web.authenticated
    async def post(self, path):
        oldConf = {}
        if path:
            if path in self._site.actions:
                oldConf = self._site.actions[path].flatten()
            else:
                raise tornado.web.HTTPError(404)

        # transfer form data into new config
        formErrors = []
        oldName = self.get_argument('oldName', None)
        if oldName != path:
            _log.error('Form error: oldName does not match path request')
            raise tornado.web.HTTPError(500)
        actionType = self.get_argument('actionType', None)
        actionName = self.get_argument('name', None)
        newConf = {"type": actionType}
        newConf['options'] = {}
        temp = self.get_argument('hostname', '')
        if temp:
            newConf['options']['hostname'] = util.toHostname(temp)
        for key in [
                'sender',
                'apikey',
                'url',
                'username',
                'password',
                'site',
        ]:
            temp = self.get_argument(key, '')
            if temp:
                newConf['options'][key] = temp
        recipients = self.get_argument('recipients', '')
        if recipients:
            newConf['options']['recipients'] = []
            recreg = set()
            for r in recipients.split():
                cr = r.lower()
                if cr not in recreg:
                    newConf['options']['recipients'].append(r)
                    recreg.add(cr)
        fallback = self.get_argument('fallback', '')
        if not fallback:
            if os.path.exists(defaults.SENDMAIL):
                fallback = defaults.SENDMAIL
        if fallback:
            newConf['options']['fallback'] = fallback

        for key in (
                'port',
                'timeout',
        ):
            temp = self.get_argument(key, '')
            if temp:
                newConf['options'][key] = int(temp)

        newInChecks = []
        for c in self.get_arguments('incheck'):
            if c in self._site.checks:
                newInChecks.append(c)

        if formErrors:
            _log.info('Action %s with form errors', path)
            status = self._site.getStatus()
            self.render("action.html",
                        status=status,
                        oldName=path,
                        curAction=curAction,
                        section='config',
                        site=self._site,
                        testMsg=testMsg,
                        formErrors=None)
            return

        # if form input ok - check changes
        async with self._site._lock:
            # remove old action from all checks
            for c in self._site.checks:
                self._site.checks[c].del_action(path)

            if path:
                # delete the old action handle
                self._site.deleteAction(path)

            # add action and add to any required checks
            self._site.addAction(actionName, newConf)
            curAction = self._site.actions[actionName]
            for c in newInChecks:
                if c in self._site.checks:
                    self._site.checks[c].add_action(curAction)

            # save out config
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.saveConfig)

        self.redirect('/action/' + self._site.pathQuote(actionName))


class CheckHandler(BaseHandler):
    """Check editor."""

    @tornado.web.authenticated
    async def get(self, path):
        check = None
        if path:
            if path in self._site.checks:
                check = self._site.checks[path]
                runopt = self.get_argument('run', '')
                if self.get_argument('delete', ''):
                    _log.info('Deleting %s without undo', path)
                    self._site.deleteCheck(path)
                    self.redirect('/checks')
                    return
                elif runopt:
                    _log.warning('Manually running %s', path)
                    await tornado.ioloop.IOLoop.current().run_in_executor(
                        None, self._site.runCheck, path)
                    retpath = '/check/' + self._site.pathQuote(path)
                    if runopt == 'list':
                        retpath = '/checks'
                    elif runopt == 'home':
                        retpath = '/'
                    self.redirect(retpath)
                    return
            else:
                raise tornado.web.HTTPError(404)
        else:
            check = util.loadCheck(name='',
                                   config={'type': 'ssh'},
                                   timezone=self._site.timezone)
            check.priority = 100 * len(self._site.checks)
        status = self._site.getStatus()
        self.render("check.html",
                    status=status,
                    oldName=path,
                    check=check,
                    section='check',
                    site=self._site,
                    formErrors=None)

    @tornado.web.authenticated
    async def post(self, path):
        oldConf = {}
        if path:
            if path in self._site.checks:
                oldConf = self._site.checks[path].flatten()
            else:
                raise tornado.web.HTTPError(404)

        # transfer form data into new config
        formErrors = []
        oldName = self.get_argument('oldName', None)
        if oldName != path:
            _log.error('Form error: oldName does not match path request')
            raise tornado.web.HTTPError(500)
        checkType = self.get_argument('checkType', None)
        checkName = self.get_argument('name', None)
        newConf = {"type": checkType}
        newConf['trigger'] = util.text2Trigger(self.get_argument(
            'trigger', ''))
        temp = self.get_argument('threshold', '')
        if temp:
            newConf['threshold'] = int(temp)
        temp = self.get_argument('retries', '')
        if temp:
            newConf['retries'] = int(temp)
        temp = self.get_argument('priority', '')
        if temp:
            newConf['priority'] = int(temp)
        else:
            if not path:
                # give new checks a default ordering > worst case: all seqs
                newConf['priority'] = 100 * len(self._site.checks)
        newConf['paused'] = bool(self.get_argument('paused', None))
        newConf['passAction'] = bool(self.get_argument('passAction', None))
        newConf['failAction'] = bool(self.get_argument('failAction', None))
        ptopic = self.get_argument('publish', None)
        if ptopic:
            newConf['publish'] = ptopic
        else:
            newConf['publish'] = None
        remid = self.get_argument('remoteId', None)
        if remid:
            newConf['remoteId'] = remid
        else:
            newConf['remoteId'] = None
        newConf['options'] = {}
        # hostname/ip
        temp = self.get_argument('hostname', '')
        if temp:
            newConf['options']['hostname'] = util.toHostname(temp)
        # string options
        for key in [
                'serialPort',
                'probe',
                'reqType',
                'reqPath',
                'reqName',
                'hostkey',
                'volume',
        ]:
            temp = self.get_argument(key, '')
            if temp:
                newConf['options'][key] = temp
        # timezone requires a little care
        temp = self.get_argument('timezone', '')
        if temp:
            newConf['options']['timezone'] = temp
            zinf = util.check.getZone(temp)
            if zinf is None:
                formErrors.append('Invalid timezone %r' % (temp))
        # int options
        for key in ['port', 'timeout', 'level', 'temperature', 'hysteresis']:
            temp = self.get_argument(key, '')
            if temp:
                newConf['options'][key] = int(temp)
        # tls & beeper default on
        temp = self.get_argument('tls', None)
        if not temp:
            newConf['options']['tls'] = False
        temp = self.get_argument('beeper', None)
        if not temp:
            newConf['options']['beeper'] = False
        # selfsigned/dnstcp is default off
        temp = self.get_argument('selfsigned', None)
        if temp:
            newConf['options']['selfsigned'] = True
        temp = self.get_argument('reqTcp', None)
        if temp:
            newConf['options']['reqTcp'] = True
        temp = self.get_arguments('checks')
        if temp:
            newConf['options']['checks'] = []
            for c in temp:
                if c:
                    newConf['options']['checks'].append(c)
        newConf['actions'] = self.get_arguments('actions')
        newConf['depends'] = self.get_arguments('depends')
        inseq = self.get_arguments('inseq')

        # final checks
        if not checkName:
            formErrors.append('Missing required check name')
        if not oldName or checkName != oldName:
            if checkName in self._site.checks:
                formErrors.append('Name already in use by another check')

        # build a temporary check object using the rest of the config
        check = util.loadCheck(name=checkName,
                               config=newConf,
                               timezone=self._site.timezone)
        for action in newConf['actions']:
            if action:
                if action in self._site.actions:
                    check.add_action(self._site.actions[action])
                else:
                    formErrors.append('Invalid action %r' % (action))
        dependReorder = False
        for depend in newConf['depends']:
            if depend:
                if depend in self._site.checks:
                    check.add_depend(self._site.checks[depend])
                    dependReorder = True
                else:
                    formErrors.append('Invalid check dependency %r' % (depend))
        inseqChange = False
        oldInseq = []
        status = self._site.getStatus()
        if oldName in status['inseqs']:
            oldInseq = status['inseqs'][oldName]
        newInseq = []
        for seq in inseq:
            if seq:
                if seq in self._site.checks:
                    if self._site.checks[seq].checkType == 'sequence':
                        newInseq.append(seq)
                    else:
                        formErrors.append('Not a sequence %r' % (seq, ))
                else:
                    formErrors.append('Invalid sequence %r' % (seq, ))
        if newInseq != oldInseq:
            inseqChange = True
            _log.info('Sequence membership change: %r != %r', newInseq,
                      oldInseq)

        if formErrors:
            _log.info('Edit check %s with form errors', path)
            status = self._site.getStatus()
            self.render("check.html",
                        status=status,
                        oldName=path,
                        check=check,
                        site=self._site,
                        section='check',
                        formErrors=formErrors)
            return

        if 'data' in oldConf:
            newConf['data'] = oldConf['data']

        # patch remoteId if name changes on a remote check
        if check.checkType == 'remote':
            if oldName and checkName != oldName and check.remoteId is None:
                _log.debug('Using oldname=%r for remoteId on remote check %r',
                           oldName, checkName)
                newConf['remoteId'] = oldName

        # if form input ok - check changes
        async with self._site._lock:
            runCheck = False
            if path:
                _log.info('Saving changes to check %s', path)
                self._site.updateCheck(path, checkName, newConf)
            else:
                _log.info('Saving new check %s', checkName)
                self._site.addCheck(checkName, newConf)
            if dependReorder:
                util.reorderSite(self._site, checkName, 'dep')
            if inseqChange:
                for seqName in oldInseq:
                    if seqName not in newInseq:
                        _log.info('Remove %s from sequence %s', checkName,
                                  seqName)
                        self._site.checks[seqName].del_check(checkName)
                if checkName in self._site.checks:
                    newCheck = self._site.checks[checkName]
                    for seqName in newInseq:
                        if seqName not in oldInseq:
                            _log.info('Add %s to sequence %s', checkName,
                                      seqName)
                            self._site.checks[seqName].add_check(newCheck)
                else:
                    raise RuntimeError('Check object/name mismatch %s' %
                                       (checkName, ))
                # force re-read and re-order of map
                self._site.checkMap(True)
                dependReorder = True
            if dependReorder:
                util.reorderSite(self._site, checkName, 'dep')

            # save out config
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.saveConfig)

        # run check and wait for result
        if runCheck:
            _log.info('Running initial test on %s', checkName)
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.runCheck, checkName)

        self.redirect('/check/' + self._site.pathQuote(checkName))


class ConfigHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self):
        status = self._site.getStatus()
        self.render("config.html",
                    status=status,
                    section='config',
                    site=self._site,
                    showusers=self.current_user == defaults.ADMINUSER,
                    formErrors=[])

    @tornado.web.authenticated
    async def post(self):
        formErrors = []
        tzUpdate = False
        temp = self.get_argument('timezone', '')
        if temp:
            zinf = util.check.getZone(temp)
            if zinf is not None:
                if self._site.timezone != zinf:
                    tzUpdate = True
                    self._site.timezone = zinf
            else:
                formErrors.append('Invalid timezone %r' % (temp))
        else:
            if self._site.timezone is not None:
                tzUpdate = True
                self._site.timezone = None

        newCfg = {'mqtt': None, 'webui': {}}
        for mkey in defaults.WEBUICONFIG:
            if mkey != 'users':
                newCfg['webui'][mkey] = defaults.WEBUICONFIG[mkey]
                if mkey in ('hostname', 'cert', 'key', 'name'):
                    temp = self.get_argument('webui.' + mkey, None)
                    if temp:
                        newCfg['webui'][mkey] = temp
                elif mkey == 'port':
                    temp = self.get_argument('webui.port', '')
                    if temp:
                        nv = None
                        if temp.isdigit():
                            temp = int(temp)
                            if temp > 0 and temp < 65536:
                                nv = temp
                        if nv is not None:
                            newCfg['webui']['port'] = nv
                        else:
                            formErrors.append('Invalid web UI port %r' %
                                              (temp))

        enableMqtt = bool(self.get_argument('mqtt.enable', None))
        if enableMqtt:
            newCfg['mqtt'] = {}
            for mkey in defaults.MQTTCONFIG:
                newCfg['mqtt'][mkey] = defaults.MQTTCONFIG[mkey]
                if mkey in ('tls', 'persist', 'retain', 'autoadd'):
                    newCfg['mqtt'][mkey] = bool(
                        self.get_argument('mqtt.' + mkey, None))
                elif mkey in ('hostname', 'username', 'password', 'clientid',
                              'basetopic'):
                    temp = self.get_argument('mqtt.' + mkey, None)
                    if temp:
                        newCfg['mqtt'][mkey] = temp
                elif mkey == 'port':
                    temp = self.get_argument('mqtt.port', '')
                    if temp:
                        nv = None
                        if temp.isdigit():
                            temp = int(temp)
                            if temp > 0 and temp < 65536:
                                nv = temp
                        if nv is not None:
                            newCfg['mqtt']['port'] = nv
                        else:
                            formErrors.append('Invalid MQTT port %r' % (temp))
                elif mkey == 'qos':
                    temp = self.get_argument('mqtt.qos', '')
                    if temp:
                        nv = None
                        if temp.isdigit():
                            temp = int(temp)
                            if temp in (0, 1, 2):
                                nv = temp
                        if nv is not None:
                            newCfg['mqtt']['qos'] = nv
                        else:
                            formErrors.append('Invalid MQTT QoS %r' % (temp))

        if formErrors:
            _log.info('Edit config with form errors')
            status = self._site.getStatus()
            self.render("config.html",
                        status=status,
                        section='config',
                        site=self._site,
                        showusers=self.current_user == defaults.ADMINUSER,
                        formErrors=formErrors)
            return

        mqttUpdate = False
        if newCfg['mqtt'] is None:
            if self._site.mqttCfg is not None:
                mqttUpdate = True
                _log.debug('Disabling MQTT interface on site')
            self._site.mqttCfg = None
            self._site.reconnectMqtt()
        else:
            for mkey in defaults.MQTTCONFIG:
                if mkey != 'debug':
                    if self._site.mqttCfg[mkey] != newCfg['mqtt'][mkey]:
                        mqttUpdate = True
                        self._site.mqttCfg[mkey] = newCfg['mqtt'][mkey]

            if mqttUpdate:
                _log.debug('Updating MQTT interface on site')
                self._site.reconnectMqtt()

        webuiUpdate = False
        for mkey in defaults.WEBUICONFIG:
            if mkey != 'users':
                if self._site.webCfg[mkey] != newCfg['webui'][mkey]:
                    webuiUpdate = True
                    self._site.webCfg[mkey] = newCfg['webui'][mkey]

        if tzUpdate or mqttUpdate or webuiUpdate:
            async with self._site._lock:
                await tornado.ioloop.IOLoop.current().run_in_executor(
                    None, self._site.saveConfig)
        if webuiUpdate:
            newUrl = 'https://%s:%s' % (self._site.webCfg['hostname'],
                                        self._site.webCfg['port'])
            # TODO: add a deferred task to restart webui (somehow)
            _log.warning('Web UI restarting at %s', newUrl)
            status = self._site.getStatus()
            self.render("reload.html",
                        status=status,
                        section='config',
                        site=self._site,
                        url=newUrl,
                        message='Web UI restarting...')
            self._site.runWebRestart()
            return
        else:
            self.redirect('/config')


class StatusHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self):
        status = self._site.getStatus()
        self.set_header("Content-Type", 'application/json')
        self.write(json.dumps(status))


class AuthLoginHandler(BaseHandler):

    async def get(self):
        self.render("login.html", error=None)

    async def post(self):
        await asyncio.sleep(0.3 + util.randbits(10) / 3000)
        un = self.get_argument('username', '')
        pw = self.get_argument('password', '')
        hash = None
        uv = None
        if un and un in self._site.webCfg['users']:
            hash = self._site.webCfg['users'][un]
            uv = un
        else:
            hash = self._site.webCfg['users']['']
            uv = None

        # checkPass has a long execution by design
        po = await tornado.ioloop.IOLoop.current().run_in_executor(
            None, util.checkPass, pw, hash)

        if uv is not None and po:
            self.set_signed_cookie("user",
                                   uv.encode('utf-8', 'replace'),
                                   expires_days=None,
                                   secure=True,
                                   samesite='Strict')
            _log.warning('Login username=%r (%s)', un, self.request.remote_ip)
            self.redirect('/')
        else:
            _log.warning('Invalid login username=%r (%s)', un,
                         self.request.remote_ip)
            self.render("login.html", error='Invalid login details')


class AuthLogoutHandler(BaseHandler):

    def get(self):
        self.clear_cookie("user", secure=True, samesite='Strict')
        self.set_header("Clear-Site-Data", '"*"')
        self.redirect('/login')


def loadUi(site):
    app = Application(site)
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(site.webCfg['cert'], site.webCfg['key'])
    port = site.webCfg['port']
    if site.webUiPort is not None:
        port = site.webUiPort
    srv = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    srv.listen(port, address=site.webCfg['hostname'])
    _log.info('Web UI listening on: https://%s:%s', site.webCfg['hostname'],
              port)
    return srv
