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
from . import mclient

basicConfig(level=DEBUG)
_log = getLogger('fletchck')
_log.setLevel(DEBUG)

# Command line options
define("config", default=None, help="specify site config file", type=str)
define("init", default=False, help="re-initialise system", type=bool)
define("port", default=None, help="specify webui listen port", type=int)
define("merge", default=None, help="merge config from file", type=str)
define("webui", default=True, help="run web ui", type=bool)


class FletchSite():
    """Wrapper object for a single fletchck site instance"""

    def __init__(self):
        self._shutdown = None
        self._lock = asyncio.Lock()
        self._mqtt = None
        self._webui = None
        self._mapCache = None
        self._bgTasks = set()

        self.base = '.'
        self.timezone = None
        self.configFile = defaults.CONFIGPATH
        self.doWebUi = True
        self.webUiPort = None
        self.log = []

        self.scheduler = None
        self.actions = None
        self.checks = None
        self.remotes = {}
        self.remoteTopics = {}
        self.webCfg = None
        self.mqttCfg = None

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

    def testAction(self, actionName):
        """Trigger notification on a single action"""
        ret = True
        if actionName in self.actions:
            _log.warning('Manually notifying action %s', actionName)
            fakeCheck = util.BaseCheck('Test Notification')
            fakeCheck.checkType = 'action-test'
            fakeCheck.failState = True
            fakeCheck.timezone = self.timezone
            fakeCheck.lastFail = util.timeString(self.timezone)
            fakeCheck.lastPass = util.timeString(self.timezone)
            fakeCheck.log = []
            fakeCheck.log.append('Testing action notification')
            fakeCheck.log.append('Fletch version: %s' % (defaults.VERSION))
            val = '%0.0f%%' % (100.0 * util.randbits(8) / 255.0, )
            fakeCheck.log.append('Some random value: %s' % (val))
            fakeCheck.level = val
            ret = True
            _log.warning('Calling trigger on %r', actionName)
            if not self.actions[actionName].trigger(fakeCheck):
                ret = False
        return ret

    def addAction(self, name, config):
        """Add the named action to site"""
        util.addAction(self, name, config)

    def hideOption(self, path, typeName, option):
        """Return a visually-hidden class for form options not in named type"""
        ret = ''
        if path and typeName in defaults.HIDEOPTIONS:
            if option in defaults.HIDEOPTIONS[typeName]:
                ret = ' visually-hidden'

        # override publish when mqtt disabled
        if option == 'publish':
            if not self._mqtt:
                ret = ' visually-hidden'

        return ret

    def copyName(self, checkName):
        """Return a clone check name not already in use on site."""
        if '-copy' in checkName:
            checkName = checkName[0:checkName.rindex('-copy')]
        newName = checkName + '-copy'
        while newName in self.checks:
            newName = '%s-copy-%s' % (checkName, util.token_hex(2))
        return newName

    def checkMap(self, recalculate=False):
        """Return a site map grouped by sorted sequences.

        Orphaned checks (those that do not appear in a sequence)
        are grouped and added to the end of the map with the key
        None.
        """
        if self._mapCache is not None and not recalculate:
            return self._mapCache

        self._mapCache = {}
        seqs = {}
        subchecks = set()
        checkList = self.sortedChecks()

        # collect all defined sequences ## TODO: check recursion (should be ok)
        for checkName in checkList:
            if self.checks[checkName].checkType == 'sequence':
                count = 0
                seqs[checkName] = []
                seq = self.checks[checkName]
                for subCheckName in seq.checks:
                    subchecks.add(subCheckName)
                    sub = self.checks[subCheckName]
                    seqs[checkName].append((sub.priority, count, subCheckName))
                    count += 1

        # reorder sequence subchecks and add to map with priority as value
        for checkName in seqs:
            self._mapCache[checkName] = {}
            seqs[checkName].sort()
            for subcheck in seqs[checkName]:
                self._mapCache[checkName][subcheck[2]] = subcheck[0]

        # add any orphaned checks to map
        self._mapCache[None] = {}
        for checkName in checkList:
            if checkName not in self._mapCache and checkName not in subchecks:
                check = self.checks[checkName]
                self._mapCache[None][checkName] = check.priority

        return self._mapCache

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

    def addRemote(self, name, checkType, remoteId=None):
        """Auto-add a remote check"""
        util.addCheck(self, name, {
            'type': 'remote',
            'subType': checkType,
            'remoteId': remoteId
        })

    def updateCheck(self, name, newName, config):
        """Update existing check to match new config"""
        util.updateCheck(self, name, newName, config)

    def deleteCheck(self, name):
        """Remove a check from a running site"""
        util.deleteCheck(self, name)

    def deleteAction(self, name):
        """Remove an acton from running site"""
        util.deleteAction(self, name)

    def updateUser(self, username, password=None, passHash=None):
        """Update or add user."""
        util.updateUser(self, username, password, passHash)

    def deleteUser(self, username):
        """Remove a user from running site."""
        util.deleteUser(self, username)

    def runCheck(self, name):
        """Run a check by name"""
        if name in self.checks:
            _log.debug('Running check %s', name)
            self.checks[name].update()
            if self.checks[name].publish:
                self.sendMsg(topic=self.checks[name].publish,
                             obj=self.checks[name].msgObj())

    def saveConfig(self):
        """Save site to config"""
        util.saveSite(self)

    def selectConfig(self):
        """Check command line and choose configuration"""
        doStart = True
        parse_command_line()
        if options.config is not None:
            # specify a desired configuration path
            self.configFile = options.config
            self.base = os.path.realpath(os.path.dirname(self.configFile))
        if not options.webui:
            _log.info('Web UI disabled by command line option')
            self.doWebUi = False
        if options.port:
            if isinstance(options.port, int):
                self.webUiPort = max(min(options.port, 65535), 1)
                if options.port != self.webUiPort:
                    _log.warning('Invalid port clamped to %d', self.webUiPort)
            else:
                _log.warning('Ignored invalid web UI port')
        if options.init:
            doStart = util.initSite(self.base, self.doWebUi, self.webUiPort)
        if self.configFile is None:
            self.configFile = defaults.CONFIGPATH
        if options.merge:
            if options.merge.lower().endswith('csv'):
                # assume CSV
                util.mergeCsv(self.base, self.configFile, options.merge)
            else:
                # assume JSON
                util.mergeConfig(self.base, self.configFile, options.merge)
        return doStart

    def getNextRun(self, checkName):
        ret = None
        if checkName in self.checks:
            if self.checks[checkName].trigger is not None:
                check = self.checks[checkName]
                job = self.scheduler.get_job(check.name)
                if job is not None:
                    if job.next_run_time is not None:
                        ret = check.timeString(job.next_run_time)
        return ret

    def getTrigger(self, check):
        return util.trigger2Text(check.trigger)

    def recvMsg(self, topic=None, message=None):
        """MQTT Message receive calback"""
        ob = mclient.fromJson(message)
        if ob is not None and isinstance(ob, dict):
            name = defaults.getOpt('name', ob, str, None)
            remoteId = None
            if name in self.remotes:
                remoteId = name
                name = self.remotes[remoteId]
                _log.debug('Using remoteId=%r for check %r', remoteId, name)
            self.remoteTopics[name] = topic
            checkType = defaults.getOpt('type', ob, str, None)
            data = defaults.getOpt('data', ob, dict, None)
            if name and checkType and data:
                if name not in self.checks:
                    if self.mqttCfg['autoadd']:
                        self.addRemote(name, checkType, remoteId)
                if name in self.checks and self.checks[
                        name].checkType == 'remote':
                    self.checks[name].remoteUpdate(checkType, data)
                else:
                    _log.info('Ignore unconfigured remote check %r', name)
            else:
                _log.info('Ignored malformed MQTT message object')
        else:
            _log.info('Ignored invalid MQTT message object')

    def sendMsg(self, topic, obj):
        """MQTT publish obj to the nominated topic"""
        if self._mqtt is not None:
            self._mqtt.publish_json(topic=topic, obj=obj)

    def clearMsg(self, topic):
        """MQTT publish NULL with retain set to the nominated topic"""
        if self._mqtt is not None:
            _log.debug('Sending NULL to topic=%s', topic)
            self._mqtt.publish(topic=topic, retain=True)

    def getStatus(self):
        status = {
            'fail': False,
            'info': None,
            'checks': {},
            'seqs': {},
            'inseqs': {},
        }
        for checkName in self.checks:
            if checkName not in status['inseqs']:
                status['inseqs'][checkName] = []
            check = self.checks[checkName]
            if check.checkType == 'sequence':
                status['seqs'][checkName] = {}
                for subCheck in check.checks:
                    status['seqs'][checkName][subCheck] = 1
                    if subCheck not in status['inseqs']:
                        status['inseqs'][subCheck] = []
                    status['inseqs'][subCheck].append(checkName)

        failCount = 0
        failCounted = set()
        for checkName in self.sortedChecks():
            check = self.checks[checkName]
            if check.failState:
                if check.checkType != 'sequence':
                    if checkName not in failCounted:
                        failCount += 1
                    failCounted.add(checkName)
                status['fail'] = True
            status['checks'][checkName] = {
                'checkType': check.checkType,
                'failState': check.failState,
                'trigger': check.trigger,
                'softFail': check.softFail if check.softFail else '',
                'lastFail': check.lastFail if check.lastFail else '',
                'lastPass': check.lastPass if check.lastPass else ''
            }
        # re-scan all checks for sequences with failing checks
        # which have not been updated in the sequence itself
        for checkName in self.checks:
            check = self.checks[checkName]
            if check.checkType != 'sequence' and check.failState:
                if checkName in status['inseqs']:
                    for seqName in status['inseqs'][checkName]:
                        if not status['checks'][seqName]['failState']:
                            _log.debug('Sequence %s with failing check: %s',
                                       seqName, checkName)
                            status['checks'][seqName]['failState'] = 'DEP'
        if failCount > 0:
            status['info'] = '%d check%s in fail state' % (
                failCount, 's' if failCount != 1 else '')
        return status

    def reconnectMqtt(self):
        """Replace site MQTT connection"""
        if self._mqtt:
            _log.debug('Disconnecting existing MQTT client')
            self._mqtt.setcb(None)
            self._mqtt.exit()
            self._mqtt = None
        if self.mqttCfg is not None:
            _log.debug('Creating new MQTT client')
            self._mqtt = mclient.Mclient(self.mqttCfg)
            self._mqtt.setcb(self.recvMsg)
            self._mqtt.start()
            if 'basetopic' in self.mqttCfg and self.mqttCfg['basetopic']:
                _log.info('Subscribe basetopic = %s',
                          self.mqttCfg['basetopic'])
                self._mqtt.subscribe(self.mqttCfg['basetopic'])

    def runWebRestart(self):
        """Arrange for a background restart of web UI"""
        task = asyncio.create_task(self.restartWebui())
        self._bgTasks.add(task)
        task.add_done_callback(self._bgTasks.discard)

    async def restartWebui(self):
        """Re-Create web UI"""
        if self._webui is not None:
            await asyncio.sleep(0)
            _log.debug('Stopping existing web server')
            self._webui.stop()
            await self._webui.close_all_connections()
            _log.debug('Web server terminated')
            self._webui = None
        _log.debug('Loading web ui module')
        from . import webui
        self._webui = webui.loadUi(self)

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

        # create mqtt client library handle
        self.reconnectMqtt()

        # create tornado application and listen on configured hostname
        if self.doWebUi and self.webCfg is not None:
            self.runWebRestart()
        else:
            _log.info('Running without webui')

        try:
            _log.warning('Starting')
            await self._shutdown.wait()
            self.saveConfig()
            if self._mqtt:
                self._mqtt.exit()
                self._mqtt.wait()
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
