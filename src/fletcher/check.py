# SPDX-License-Identifier: MIT
"""Check base class"""

from datetime import datetime
from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR

_log = getLogger('check')
_log.setLevel(DEBUG)

CHECK_TYPES = {}


def timestamp():
    return datetime.now().astimezone().isoformat()


def loadCheck(config):
    """Create and return a check object for the provided flat config"""
    ret = None
    if config['type'] in CHECK_TYPES:
        name = config['type']
        if 'name' in config and isinstance(config['name'], str):
            name = config['name']
        options = {}
        if 'options' in config and isinstance(config['options'], dict):
            options = config['options']
        ret = CHECK_TYPES[config['type']](name, options)
        if 'threshold' in config and isinstance(config['threshold'], int):
            if config['threshold'] > 0:
                ret.threshold = config['threshold']
        if 'failTrigger' in config and isinstance(config['failTrigger'], bool):
            ret.failTrigger = config['failTrigger']
        if 'passTrigger' in config and isinstance(config['passTrigger'], bool):
            ret.passTrigger = config['passTrigger']
        if 'data' in config:
            if 'failState' in config['data']:
                if isinstance(config['data']['failState'], bool):
                    ret.failState = config['data']['failState']
            if 'failCount' in config['data']:
                if isinstance(config['data']['failCount'], int):
                    if config['data']['failCount'] >= 0:
                        ret.failCount = config['data']['failCount']
            if 'threshold' in config['data']:
                if isinstance(config['data']['threshold'], int):
                    if config['data']['threshold'] >= 0:
                        ret.threshold = config['data']['threshold']
            if 'lastFail' in config['data']:
                if isinstance(config['data']['lastFail'], str):
                    ret.lastFail = config['data']['lastFail']
            if 'lastPass' in config['data']:
                if isinstance(config['data']['lastPass'], str):
                    ret.lastPass = config['data']['lastPass']
            if 'log' in config['data']:
                if isinstance(config['data']['log'], list):
                    ret.log = config['data']['log']
    else:
        _log.warning('Invalid action type ignored')
    return ret


class check():
    """Check base class"""

    def __init__(self, name, options={}):
        self.name = name
        self.failTrigger = True
        self.passTrigger = True
        self.threshold = 1
        self.options = options
        self.checkType = 'dummy'

        self.actions = {}

        self.failState = False
        self.failCount = 0
        self.log = []
        self.lastFail = None
        self.lastPass = None

    def _runCheck(self):
        """Perform the required check and return fail state"""
        return False

    def notify(self):
        """Trigger all configured actions"""
        for action in self.actions:
            self.actions[action].trigger(self)

    def update(self):
        """Run check, update state and trigger events as required"""
        curFail = self._runCheck()
        _log.debug('%s cur=%r prev=%r count=%r', self.name, curFail,
                   self.failState, self.failCount)

        if curFail:
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    _log.info('%s => fail', self.name)
                    self.failState = True
                    self.lastFail = timestamp()
                    if self.failTrigger:
                        self.notify()
        else:
            self.failCount = 0
            self.log.clear()
            if self.failState:
                _log.info('%s => pass', self.name)
                self.failState = False
                self.lastPass = timestamp()
                if self.passTrigger:
                    self.notify()

        return True

    def add_action(self, name, action):
        """Add the specified action"""
        self.actions[name] = action

    def del_action(self, name):
        """Remove the specified action"""
        if name in self.actions:
            del self.actions[name]

    def flatten(self):
        """Return the check as a flattened dictionary"""
        actList = [a for a in self.actions]
        return {
            'name': self.name,
            'type': self.checkType,
            'threshold': self.threshold,
            'failTrigger': self.failTrigger,
            'passTrigger': self.passTrigger,
            'options': self.options,
            'actions': actList,
            'data': {
                'failState': self.failState,
                'failCount': self.failCount,
                'log': self.log,
                'lastFail': self.lastFail,
                'lastPass': self.lastPass
            }
        }


CHECK_TYPES['dummy'] = check
