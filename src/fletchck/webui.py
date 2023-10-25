# SPDX-License-Identifier: MIT
"""Fletchck Web Interface"""

import asyncio
import ssl
import tornado.web
import tornado.ioloop
import tornado.template
import json
from importlib.resources import files
from . import defaults
from . import util
from logging import getLogger, DEBUG, INFO, WARNING

_log = getLogger('fletchck.webui')
_log.setLevel(INFO)


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
            (r"/check/(.*)", CheckHandler, dict(site=site)),
            (r"/actions", ActionsHandler, dict(site=site)),
            (r"/login", AuthLoginHandler, dict(site=site)),
            (r"/log", LogHandler, dict(site=site)),
            (r"/status", StatusHandler, dict(site=site)),
            (r"/logout", AuthLogoutHandler, dict(site=site)),
        ]
        templateLoader = PackageLoader(whitespace='all')
        settings = dict(
            site_version=defaults.VERSION,
            site_name=site.webCfg['name'],
            autoreload=False,
            serve_traceback=site.webCfg['debug'],
            static_path='static',
            static_url_prefix='/s/',
            static_handler_class=PackageFileHandler,
            template_loader=templateLoader,
            cookie_secret=util.token_hex(32),
            login_url='/login',
            debug=True,
        )
        super().__init__(handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):

    def initialize(self, site):
        self._site = site

    def get_current_user(self):
        return self.get_signed_cookie("user", max_age_days=defaults.AUTHEXPIRY)

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

    @tornado.web.authenticated
    async def get(self):
        status = self._site.getStatus()
        self.render("home.html",
                    site=self._site,
                    status=status,
                    section='check')


class LogHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self):
        if self.get_argument('clear', ''):
            _log.info('Clearing volatile log')
            self._site.log.clear()
        status = self._site.getStatus()
        self.render("log.html", site=self._site, status=status, section='log')


class CheckHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self, path):
        check = None
        if path:
            if path in self._site.checks:
                check = self._site.checks[path]
                if self.get_argument('delete', ''):
                    _log.info('Deleting %s without undo', path)
                    self._site.deleteCheck(path)
                    self.redirect('/')
                    return
                elif self.get_argument('run', ''):
                    _log.info('Manually running %s', path)
                    await tornado.ioloop.IOLoop.current().run_in_executor(
                        None, self._site.runCheck, path)
                    self.redirect('/check/' + self._site.pathQuote(path))
                    return
            else:
                raise tornado.web.HTTPError(404)
        else:
            check = util.check.loadCheck(name='',
                                         config={'type': 'ssh'},
                                         timezone=self._site.timezone)
            check.priority = len(self._site.checks)
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
        temp = self.get_argument('priority', '')
        if temp:
            newConf['priority'] = int(temp)
        else:
            if not path:
                # give new checks a reasonable default ordering
                newConf['priority'] = len(self._site.checks)
        newConf['passAction'] = bool(self.get_argument('passAction', None))
        newConf['failAction'] = bool(self.get_argument('failAction', None))
        newConf['options'] = {}
        # string options
        for key in ['hostname', 'probe', 'reqType', 'reqPath', 'hostkey']:
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
        for key in ['port', 'timeout']:
            temp = self.get_argument(key, '')
            if temp:
                newConf['options'][key] = int(temp)
        # tls is default on
        temp = self.get_argument('tls', None)
        if not temp:
            newConf['options']['tls'] = False
        # selfsigned is default off
        temp = self.get_argument('selfsigned', None)
        if temp:
            newConf['options']['selfsigned'] = True
        temp = self.get_arguments('checks')
        if temp:
            newConf['options']['checks'] = []
            for c in temp:
                if c:
                    newConf['options']['checks'].append(c)
        newConf['actions'] = self.get_arguments('actions')
        newConf['depends'] = self.get_arguments('depends')

        # final checks
        if not checkName:
            formErrors.append('Missing required check name')
        if not oldName or checkName != oldName:
            if checkName in self._site.checks:
                formErrors.append('Name already in use by another check')

        # build a temporary check object using the rest of the config
        check = util.check.loadCheck(name=checkName,
                                     config=newConf,
                                     timezone=self._site.timezone)
        for action in newConf['actions']:
            if action:
                if action in self._site.actions:
                    check.add_action(self._site.actions[action])
                else:
                    formErrors.append('Invalid action %r' % (action))
        for depend in newConf['depends']:
            if depend:
                if depend in self._site.checks:
                    check.add_depend(self._site.checks[depend])
                else:
                    formErrors.append('Invalid check dependency %r' % (depend))

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

        # if form input ok - check changes
        async with self._site._lock:
            runCheck = False
            if path:
                _log.info('Saving changes to check %s', path)
                self._site.updateCheck(path, checkName, newConf)
            else:
                _log.info('Saving new check %s', checkName)
                self._site.addCheck(checkName, newConf)
                runCheck = True

            # save out config
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.saveConfig)

        # run check and wait for result
        if runCheck:
            _log.info('Running initial test on %s', checkName)
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.runCheck, checkName)

        if path:
            self.redirect('/check/' + self._site.pathQuote(checkName))
        else:
            self.redirect('/')


class ActionsHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self):
        testMsg = None
        if 'email' not in self._site.actions:
            self._site.addAction('email', {'type': 'email'})
        if 'sms' not in self._site.actions:
            self._site.addAction('sms', {'type': 'sms'})

        if self.get_argument('test', ''):
            _log.info('Sending test notifications')
            res = await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.testActions)
            _log.debug('After waiting - res = %r', res)
            if not res:
                testMsg = 'One or more tests failed, check log for details.'

        status = self._site.getStatus()
        self.render("actions.html",
                    status=status,
                    testMsg=testMsg,
                    section='actions',
                    site=self._site,
                    formErrors=[])

    @tornado.web.authenticated
    async def post(self):
        # transfer form data into options
        emailOptions = {}
        smsOptions = {}

        # list options
        nv = self.get_argument('email.recipients', '')
        if nv:
            nv = nv.split()
            if nv:
                emailOptions['recipients'] = nv
        nv = self.get_argument('sms.recipients', '')
        if nv:
            nv = nv.split()
            if nv:
                smsOptions['recipients'] = nv

        # string options
        for key in [
                'site', 'hostname', 'username', 'password', 'sender', 'url'
        ]:
            nv = self.get_argument('email.' + key, '')
            if nv:
                emailOptions[key] = nv
            nv = self.get_argument('sms.' + key, '')
            if nv:
                smsOptions[key] = nv

        # int options
        for key in ['port', 'timeout']:
            nv = self.get_argument('email.' + key, '')
            if nv:
                emailOptions[key] = int(nv)
            nv = self.get_argument('sms.' + key, '')
            if nv:
                smsOptions[key] = int(nv)

        async with self._site._lock:
            self._site.actions['email'].options = emailOptions
            self._site.actions['sms'].options = smsOptions
            await tornado.ioloop.IOLoop.current().run_in_executor(
                None, self._site.saveConfig)
        self.redirect('/actions')


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
                                   uv,
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
    srv = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    srv.listen(site.webCfg['port'], address=site.webCfg['hostname'])
    _log.info('Web UI listening on: https://%s:%s', site.webCfg['hostname'],
              site.webCfg['port'])
