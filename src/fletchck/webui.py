# SPDX-License-Identifier: MIT
"""Fletchck Web Interface"""

import asyncio
import ssl
import tornado.web
import tornado.ioloop
import tornado.template
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


class Application(tornado.web.Application):

    def __init__(self, site):
        handlers = [
            (r"/", HomeHandler, dict(site=site)),
            (r"/login", AuthLoginHandler, dict(site=site)),
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
            xsrf_cookies=True,
            xsrf_cookie_kwargs={
                'secure': True,
                'samesite': 'Strict'
            },
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


class HomeHandler(BaseHandler):

    @tornado.web.authenticated
    async def get(self):
        entries = []
        self.render("dash.html", entries=entries)


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
            self.clear_cookie("_xsrf", secure=True, samesite='Strict')
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error='Invalid login details')


class AuthLogoutHandler(BaseHandler):

    def get(self):
        self.clear_cookie("user", secure=True, samesite='Strict')
        self.clear_cookie("_xsrf", secure=True, samesite='Strict')
        self.set_header("Clear-Site-Data", '"*"')
        self.redirect(self.get_argument("next", "/"))


def loadUi(site):
    app = Application(site)
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(site.webCfg['cert'], site.webCfg['key'])
    srv = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    srv.listen(site.webCfg['port'], address=site.webCfg['hostname'])
    _log.info('Web UI listening on: https://%s:%s', site.webCfg['hostname'],
              site.webCfg['port'])
