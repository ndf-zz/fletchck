# SPDX-License-Identifier: MIT
"""Fletcher application class"""

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

VERSION = '1.0.0a1'

# TEMP
basicConfig(level=DEBUG)
_log = getLogger('fletcher')
_log.setLevel(DEBUG)

# Command line options
define("config", default=None, help="specify site config file", type=str)
define("init", default=False, help="re-initialise system", type=bool)


class Application(tornado.web.Application):

    def __init__(self, cfg):
        basepath = os.path.realpath(cfg['base'])
        _log.debug('Creating application object at %r', basepath)
        handlers = [
            (r"/", HomeHandler, dict(cfg=cfg)),
            (r"/login", AuthLoginHandler, dict(cfg=cfg)),
            (r"/logout", AuthLogoutHandler, dict(cfg=cfg)),
        ]
        settings = dict(
            site_version=VERSION,
            site_name=cfg['name'],
            autoreload=False,
            serve_traceback=cfg['debug'],
            template_path=os.path.join(basepath, defaults.TEMPLATEPATH),
            static_path=os.path.join(basepath, defaults.STATICPATH),
            static_url_prefix='/s/',
            static_handler_class=OvrFileHandler,
            xsrf_cookies=True,
            xsrf_cookie_kwargs={
                'secure': True,
                'samesite': 'Strict'
            },
            cookie_secret=util.token_hex(32),
            login_url='/login',
            debug=True,
        )
        super().__init__(handlers, **settings)


class NoResultError(Exception):
    pass


class OvrFileHandler(tornado.web.StaticFileHandler):

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
        if un and un in self._db['users']:
            hash = self._db['users'][un]
            uv = un
        else:
            hash = self._db['users']['']
            uv = None

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


async def runApp():
    # check command line
    tornado.options.parse_command_line()
    configFile = None
    if options.config is not None:
        configFile = options.config
        if not os.path.exists(options.config):
            _log.warning('Config file not found')
            configFile = None
    if options.init:
        # (re)init site from current working directory
        util.initSite('.')

    # initialise site
    if configFile is None:
        configFile = os.path.join(defaults.CONFIGPATH, 'config')
    siteConf = util.loadSite(configFile)
    if siteConf is None:
        _log.error('Error reading site config')
        raise RuntimeError('Error reading site config')

    # load runtime web assets
    util.loadAssets(siteConf['base'])

    # create tornado application and listen on configured hostname
    app = Application(siteConf)
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(siteConf['cert'], siteConf['key'])
    srv = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    srv.listen(siteConf['port'], address=siteConf['host'])
    _log.info('Fletcher listening on: %s:%s', siteConf['host'],
              siteConf['port'])
    shutdown_event = tornado.locks.Event()
    await shutdown_event.wait()


def main():
    return asyncio.run(runApp())


if __name__ == "__main__":
    main()
