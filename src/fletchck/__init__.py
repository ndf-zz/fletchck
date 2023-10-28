# SPDX-License-Identifier: MIT
"""Fletchck application"""

import asyncio
import os.path
from tornado.options import parse_command_line, define, options
from . import util
from . import defaults
from urllib.parse import quote as pathQuote
from logging import getLogger, DEBUG, INFO, WARNING, basicConfig, Formatter
from signal import SIGTERM

basicConfig(level=INFO)
_log = getLogger('fletchck')
_log.setLevel(INFO)

# Command line options
define("config", default=None, help="specify site config file", type=str)
define("init", default=False, help="re-initialise system", type=bool)
define("webui", default=True, help="run web ui", type=bool)


class FletchSite():
    """Wrapper object for a single fletchck site instance"""

    def __init__(self):
        self._shutdown = None
        self._lock = asyncio.Lock()

        self.base = '.'
        self.timezone = None
        self.configFile = defaults.CONFIGPATH
        self.doWebUi = True
        self.log = []

        self.scheduler = None
        self.actions = None
        self.checks = None
        self.webCfg = None

    def _sigterm(self):
        """Handle TERM signal"""
        _log.warning('Site terminated by SIGTERM')
        self._shutdown.set()

    @classmethod
    def pathQuote(cls, path):
        """URL escape path element for use in link text"""
        return pathQuote(path, safe='')

    def loadConfig(self):
        """Load site from config"""
        util.loadSite(self)

    def testActions(self):
        """Trigger notifications to email and sms actions"""
        _log.warning('Manually notifying email and sms')
        fakeCheck = util.check.BaseCheck('Notification')
        fakeCheck.checkType = 'action-test'
        fakeCheck.failState = False
        fakeCheck.timezone = self.timezone
        fakeCheck.lastPass = util.check.timeString(self.timezone)
        fakeCheck.log = ['Testing action notification to:', 'email', 'sms']
        emailOK = False
        if 'email' in self.actions:
            emailOK = self.actions['email'].trigger(fakeCheck)
        smsOK = False
        if 'sms' in self.actions:
            smsOK = self.actions['sms'].trigger(fakeCheck)
        return emailOK and smsOK

    def addAction(self, name, config):
        """Add the named action to site"""
        util.addAction(self, name, config)

    def sortedChecks(self):
        """Return the list of check names in priority order"""
        aux = []
        count = 0
        for name in self.checks:
            aux.append((self.checks[name].priority, count, name))
            count += 1
        aux.sort()
        return [n[2] for n in aux]

    def addCheck(self, name, config):
        """Add the named check to site"""
        util.addCheck(self, name, config)

    def updateCheck(self, name, newName, config):
        """Update existing check to match new config"""
        util.updateCheck(self, name, newName, config)

    def deleteCheck(self, name):
        """Remove a check from a running site"""
        util.deleteCheck(self, name)

    def runCheck(self, name):
        """Run a check by name"""
        if name in self.checks:
            _log.debug('Running check %s', name)
            self.checks[name].update()

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
        if not options.webui:
            _log.info('Web UI disabled by command line option')
            self.doWebUi = False
        if options.init:
            # (re)init site from current base directory
            if not util.initSite(self.base, self.doWebUi):
                return False
        if self.configFile is None:
            self.configFile = defaults.CONFIGPATH
        return True

    def getTrigger(self, check):
        return util.trigger2Text(check.trigger)

    def getStatus(self):
        status = {'fail': False, 'info': None, 'checks': {}}
        failCount = 0
        for checkName in self.sortedChecks():
            check = self.checks[checkName]
            if check.failState:
                failCount += 1
                status['fail'] = True
            status['checks'][checkName] = {
                'checkType': check.checkType,
                'failState': check.failState,
                'trigger': check.trigger,
                'softFail': check.softFail if check.softFail else '',
                'lastFail': check.lastFail if check.lastFail else '',
                'lastPass': check.lastPass if check.lastPass else ''
            }
        if failCount > 0:
            status['info'] = '%d check%s in fail state' % (
                failCount, 's' if failCount > 1 else '')
        return status

    async def run(self):
        """Load and run site in async loop"""
        rootLogger = getLogger()
        logHandler = util.LogHandler(self)
        logHandler.setLevel(WARNING)
        logHandler.setFormatter(Formatter(defaults.LOGFORMAT))
        rootLogger.addHandler(logHandler)

        self.loadConfig()
        if self.scheduler is None:
            _log.error('Error reading site config')
            return -1

        self._shutdown = asyncio.Event()
        asyncio.get_running_loop().add_signal_handler(SIGTERM, self._sigterm)

        # create tornado application and listen on configured hostname
        if self.doWebUi and self.webCfg is not None:
            _log.debug('Loading web ui module')
            from . import webui
            webui.loadUi(self)
        else:
            _log.info('Running without webui')

        try:
            _log.warning('Starting')
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
