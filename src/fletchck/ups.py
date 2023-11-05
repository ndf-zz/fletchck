# SPDX-License-Identifier: MIT
"""UPS Protocol Support"""

import serial
from logging import getLogger, DEBUG, INFO, WARNING
from time import sleep

_log = getLogger('fletchck.ups')
_log.setLevel(INFO)

# Constants
_ENCODING = 'ascii'


class UpsQsV:
    """UPS 'QS' V Protocol

    Tested with Ninja PSLN600 

    Refer: https://networkupstools.org/protocols/voltronic-qs.html
    """

    def __init__(self, port):
        self._port = serial.Serial(port, 2400, timeout=0.5)
        self.error = False
        self.inputVolts = None
        self.outputVolts = None
        self.load = None
        self.battery = None
        self.fail = False
        self.lowBattery = False
        self.fault = False
        self.testing = False
        self.shutdown = False
        self.beeper = False

    def _write(self, buf):
        _log.debug('SEND: %r', buf)
        return self._port.write(buf.encode(_ENCODING))

    def _read(self, count=1024):
        rcv = self._port.read(count).decode(_ENCODING)
        if rcv == '':
            _log.debug('RECV: [timeout]')
        else:
            _log.debug('RECV: %r', rcv)
        return rcv

    def _command(self, query, responseRequired=True):
        """Send command and wait for reply"""
        self._write(query)
        rcv = self._read()
        if rcv:
            if rcv == query:
                _log.error('Invalid UPS command %r', query)
                rcv = ''
        else:
            if responseRequired:
                _log.debug('Timout waiting for UPS reply')
                self.error = True
        return rcv

    def update(self):
        """Fetch and decode status from connected UPS

        (243.5 245.7 245.4 000 49.8 13.7 --.- 00001000\r
        """
        stat = self._command('QS\r')
        if stat.startswith('('):
            sv = stat[1:-1].split()
            if len(sv) == 8:
                self.inputVolts = float(sv[0])
                self.outputVolts = float(sv[2])
                self.load = int(sv[3])
                self.battery = float(sv[5])
                flags = sv[7]
                self.fail = True if flags[0] == '1' else False
                self.lowBattery = True if flags[1] == '1' else False
                self.fault = True if flags[3] == '1' else False
                self.testing = True if flags[5] == '1' else False
                self.shutdown = True if flags[6] == '1' else False
                self.beeper = True if flags[7] == '1' else False
            else:
                raise RuntimeError('Invalid UPS status: %r' % (stat, ))
        else:
            raise RuntimeError('Invalid UPS status: %r' % (stat, ))
        if self.load > 85:
            _log.warning('High load detected: %d%%', self.load)
        if self.lowBattery:
            _log.warning('Low battery: %0.1fV', self.battery)

    def getInfo(self, update=True):
        if update:
            self.update()
        return 'Fail: %r, Low Battery: %r, Fault: %r, Shutdown: %r, Beeper: %r' % (
            self.fail, self.lowBattery, self.fault, self.shutdown, self.beeper)

    def setShutdown(self, delay=5, recover=5):
        """Shutdown in delay min for recovery after recover minutes of power"""
        if delay < 1:
            delay = 1
        self.update()
        if self.shutdown:
            _log.info('UPS already shutdown')
        cmd = 'S%02dR%04d\r' % (delay, recover)
        return self._command(cmd, responseRequired=False)

    def cancelShutdown(self):
        self.update()
        if not self.shutdown:
            _log.debug('UPS already online')
        self._command('C\r', responseRequired=False)

    def runTest(self):
        """Request a self-test, wait for outcome and return status"""
        self.update()
        if self.fail:
            _log.info('UPS in fail state, test not started')
            return (True, 'UPS in fail state, test not started')
        if self.shutdown:
            _log.info('UPS in shutdown state, test not started')
            return (True, 'UPS in fail state, test not started')
        if self.battery < 13.0:
            _log.info('Low battery %0.1fV, test not started', self.battery)
            return (True, 'Low battery, test not started')
        if self.fault:
            _log.warning('UPS already in fault, test may not pass')

        testLoad = 0
        testVolts = 0.0
        self._command('T\r', responseRequired=False)
        while True:
            self.update()
            if not self.testing:
                break
            if self.load > testLoad:
                testLoad = self.load
            testVolts = self.battery
            _log.debug('Testing: Load=%d%%, Battery=%0.1fV', self.load,
                       self.battery)
            sleep(1)
        _log.debug('Test concluded, Fault: %r', self.fault)
        message = 'Peak load: %d%%, Battery: %0.1fV' % (testLoad, testVolts)
        return (self.fault, message)

    def setBeeper(self, beeper):
        """Set the UPS beeper to the desired value"""
        self.update()
        if self.beeper != beeper:
            self._command('Q\r', responseRequired=False)
