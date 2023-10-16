# SPDX-License-Identifier: MIT
"""Fletchck application class"""

import asyncio
import os.path
import ssl
import tornado.web
import tornado.locks
import tornado.ioloop
from tornado.options import define, options
from . import util
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, basicConfig
from signal import SIGTERM

VERSION = '1.0.0a1'

# TEMP
basicConfig(level=DEBUG)
_log = getLogger('fletchck')
_log.setLevel(DEBUG)

# Command line options
define("config", default=None, help="specify site config file", type=str)
define("init", default=False, help="re-initialise system", type=bool)
define("webui", default=True, help="run web ui", type=bool)


class Application(tornado.web.Application):

    def __init__(self, cfg):
        basepath = os.path.realpath(cfg['base'])
        _log.debug('Creating tornado application object at %r', basepath)
        handlers = [
            (r"/", HomeHandler, dict(cfg=cfg)),
            (r"/login", AuthLoginHandler, dict(cfg=cfg)),
            (r"/logout", AuthLogoutHandler, dict(cfg=cfg)),
        ]
        templateLoader = util.PackageLoader(whitespace='all')
        settings = dict(
            site_version=VERSION,
            site_name=cfg['webui']['name'],
            autoreload=False,
            serve_traceback=cfg['webui']['debug'],
            static_path='static',
            static_url_prefix='/s/',
            static_handler_class=util.PackageFileHandler,
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


class NoResultError(Exception):
    pass


class BaseHandler(tornado.web.RequestHandler):

    def initialize(self, cfg):
        self._db = cfg

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
        if un and un in self._db['webui']['users']:
            hash = self._db['webui']['users'][un]
            uv = un
        else:
            hash = self._db['webui']['users']['']
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
            self.render("login.html", error="Invalid login details")


class AuthLogoutHandler(BaseHandler):

    def get(self):
        self.clear_cookie("user", secure=True, samesite='Strict')
        self.clear_cookie("_xsrf", secure=True, samesite='Strict')
        self.set_header("Clear-Site-Data", '"*"')
        self.redirect(self.get_argument("next", "/"))


class FletchSite():
    """Wrapper object for a single fletchck site instance"""

    def __init__(self):
        self._configFile = None
        self._config = {}
        self._shutdown = None
        self._webUi = True
        self._srv = None

    def _sigterm(self):
        """Handle TERM signal"""
        _log.info('Site terminated by SIGTERM')
        self._shutdown.set()

    def loadConfig(self):
        """Load site from config"""
        if self._configFile is None:
            self._configFile = defaults.CONFIGPATH
        if os.path.exists(self._configFile):
            self._config = util.loadSite(self._configFile)

    def saveConfig(self):
        """Save site to config"""
        util.saveSite(self._config, self._configFile)

    def selectConfig(self):
        """Check command line and choose configuration"""
        tornado.options.parse_command_line()
        if options.config is not None:
            if options.init:
                _log.error('Option "config" may not be specified with "init"')
                return False
            self._configFile = options.config
            if not os.path.exists(options.config):
                _log.warning('Config file not found')
                self._configFile = None
        if options.init:
            # (re)init site from current working directory
            if not util.initSite('.'):
                return False
        if not options.webui:
            _log.info('Web UI disabled by command line option')
            self._webUi = False
        return True

    async def run(self):
        """Load and run site in async loop"""
        self.loadConfig()
        if self._config is None:
            _log.error('Error reading site config')
            return -1

        # Add TERM handler
        self._shutdown = asyncio.Event()
        asyncio.get_running_loop().add_signal_handler(SIGTERM, self._sigterm)

        # create tornado application and listen on configured hostname
        if self._webUi and 'webui' in self._config and isinstance(
                self._config['webui'], dict):
            app = Application(self._config)
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(self._config['webui']['cert'],
                                    self._config['webui']['key'])
            srv = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
            srv.listen(self._config['webui']['port'],
                       address=self._config['webui']['host'])
            _log.info('Web UI listening on: https://%s:%s',
                      self._config['webui']['host'],
                      self._config['webui']['port'])
            self._srv = srv
        else:
            _log.info('Running without webui')

        try:
            await self._shutdown.wait()
            self.saveConfig()
            if self._srv is not None:
                _log.info('Shutting down web ui')
                self._srv.stop()
                await self._srv.close_all_connections()
        except Exception as e:
            _log.error('run %s: %s', e.__class__.__name__, e)

        return 0


def main():
    site = FletchSite()
    if site.selectConfig():
        return asyncio.run(site.run())


if __name__ == "__main__":
    main()
