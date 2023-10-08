# SPDX-License-Identifier: MIT
"""Action base and specific classes"""

from . import defaults
from logging import getLogger, DEBUG, INFO, WARNING, ERROR

_log = getLogger('action')
_log.setLevel(DEBUG)

ACTION_TYPES = {}


def loadAction(config):
    """Return an action object for the provided config dict"""
    ret = None
    if config['type'] in ACTION_TYPES:
        name = config['type']
        if 'name' in config and isinstance(config['name'], str):
            name = config['name']
        description = config['type']
        if 'description' in config and isinstance(config['description'], str):
            description = config['description']
        options = {}
        if 'options' in config and isinstance(config['options'], str):
            options = config['options']
        ret = ACTION_TYPES[config['type']](name, description, options)
    else:
        _log.warning('Invalid action type ignored')
    return ret


class action():
    """Action base class, implements the log type and interface"""

    def __init__(self, name=None, description=None, options={}):
        self.name = name
        self.description = description
        self.options = options
        self.actionType = 'log'

    def trigger(self, source):
        """Fire the action with the provided context"""
        msg = 'Pass'
        if source.failState:
            msg = 'Fail'
        _log.info('%s %s: %s', self.name, source.name, msg)
        return True

    def flatten(self):
        """Return the action detail as a flattened dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'options': self.options,
            'type': self.actionType
        }


ACTION_TYPES['log'] = action


class sendEmail(action):
    """Send email by configured submit"""
    pass


ACTION_TYPES['email'] = sendEmail


class apiSms(action):
    """Post SMS via smscentral api"""
    pass


ACTION_TYPES['sms'] = apiSms


class dbusSms(action):
    """Post sms with ModemManager via dbus"""
    pass


ACTION_TYPES['mm'] = dbusSms


class webHook(action):
    """Call web hook"""
    pass


ACTION_TYPES['web'] = webHook
