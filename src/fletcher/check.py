# SPDX-License-Identifier: MIT
"""Check base class"""

from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR

# temp
from secrets import randbits

_log = getLogger('check')
_log.setLevel(DEBUG)


class check():
    """Check base class"""

    def __init__(self, name, threshold, options={}):
        self.name = name
        self.options = options
        self.threshold = threshold

        self.failState = False
        self.failCount = 0
        self.actions = {}

    def _runCheck(self):
        """Perform the required check"""
        return randbits(8) > 150

    def notify(self):
        """Trigger all configured actions"""
        for action in self.actions:
            self.actions[action].trigger(self)

    def update(self):
        """Run check, update state and trigger events as required"""
        nextState = self._runCheck()
        _log.debug('%s cur=%r fail=%r count=%r', self.name, nextState,
                   self.failState, self.failCount)

        if nextState:
            self.failCount += 1
            if self.failCount >= self.threshold:
                if not self.failState:
                    _log.info('%s goes into fail', self.name)
                    self.failState = True
                    self.notify()
        else:
            self.failCount = 0
            if self.failState:
                _log.info('%s return from fail', self.name)
                self.failState = False
                self.notify()

        return True

    def add_action(self, name, action):
        """Add the specified action"""
        self.actions[name] = action

    def del_action(self, name):
        """Remove the specified action"""
        if name in self.actions:
            del self.actions[name]
