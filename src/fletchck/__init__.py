# SPDX-License-Identifier: MIT
"""Fletchck application"""

import asyncio
import os.path
from tornado.options import parse_command_line, define, options
from . import util
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, basicConfig
from signal import SIGTERM

VERSION = '1.0.0a1'

basicConfig(level=DEBUG)
_log = getLogger('fletchck')
_log.setLevel(DEBUG)

# Command line options
define("config", default=None, help="specify site config file", type=str)
define("init", default=False, help="re-initialise system", type=bool)
define("webui", default=True, help="run web ui", type=bool)


class FletchSite():
    """Wrapper object for a single fletchck site instance"""

    def __init__(self):
        self._shutdown = None

        self.base = '.'
        self.configFile = defaults.CONFIGPATH
        self.doWebUi = True

        self.scheduler = None
        self.actions = None
        self.checks = None
        self.webCfg = None
        self.httpSrv = None

    def _sigterm(self):
        """Handle TERM signal"""
        _log.info('Site terminated by SIGTERM')
        self._shutdown.set()

    def loadConfig(self):
        """Load site from config"""
        util.loadSite(self)

    def saveConfig(self):
        """Save site to config"""
        util.saveSite(self)

    def selectConfig(self):
        """Check command line and choose configuration"""
        parse_command_line()
        if options.config is not None:
            # specify a desired configuration path
            self.configFile = options.config
            self.base = os.path.realpath(os.path.dirname(self.configFile))
        if options.init:
            # (re)init site from current base directory
            if not util.initSite(self.base):
                return False
        if not options.webui:
            _log.info('Web UI disabled by command line option')
            self.doWebUi = False
        if self.configFile is None:
            self.configFile = defaults.CONFIGPATH
        return True

    async def run(self):
        """Load and run site in async loop"""
        self.loadConfig()
        if self.scheduler is None:
            _log.error('Error reading site config')
            return -1

        self._shutdown = asyncio.Event()
        asyncio.get_running_loop().add_signal_handler(SIGTERM, self._sigterm)

        # create tornado application and listen on configured hostname
        if self.doWebUi and self.webCfg is not None:
            util.loadUi(self)
        else:
            _log.info('Running without webui')

        try:
            await self._shutdown.wait()
            self.saveConfig()
        except Exception as e:
            _log.error('main %s: %s', e.__class__.__name__, e)

        return 0


def main():
    site = FletchSite()
    if site.selectConfig():
        if site.base and site.base != '.':
            if os.path.exists(site.base):
                os.chdir(site.base)
            else:
                _log.error('Path to site config does not exist')
                return -1
        return asyncio.run(site.run())
