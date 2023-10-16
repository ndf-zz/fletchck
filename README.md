# fletchck

Fletchck is a self-contained service monitor.
It provides a suite of simple internet service probes
called "checks", with flexible scheduling provided by
[APScheduler](https://apscheduler.readthedocs.io/en/master/).
Service checks trigger notification actions
as they transition from pass to fail or vice-versa.
Configuration is via JSON file or an in-built web
user interface.

The following anonymous checks are supported:

   - SMTP: SMTP with optional starttls
   - SMTP-over-SSL: Submissions
   - IMAP4-SSL: IMAP mailbox
   - HTTPS: HTTP request
   - Cert: Check TLS certificate validity and/or expiry
   - SSH: SSH pre-auth connection with optional hostkey check
   - Sequence: A sequence of checks, fails if any one check fails

The following notification actions are supported:

   - Email: Send an email
   - API SMS: Post SMS via SMS Central API
   - Log

## Installation

Create a python virtual env, and install from pypi using pip:

	$ python3 -m venv --system-site-packages venv
	$ ./venv/bin/pip3 install fletchck

## Setup

Create a new empty site configuration in the current
directory with the -init option:

	$ ./venv/bin/fletchck -init

Follow the prompts to start the newly created service,
or start using the configuration file path:

	$ ./venv/bin/fletchck --config=config/config

To run without a web user interface, use the --webui
command line option:

	$ ./venv/bin/fletchck --webui=false

## Requirements

   - python > 3.9
   - apscheduler
   - tornado
   - paramiko
   - passlib
   - cryptography

## Scheduling

Job scheduling is handled by APScheduler by associating
a trigger of type interval or cron to a check.

### Interval

The configured check is scheduled to be run
at a repeating interval of the specified
duration of weeks, days, hours, minutes and seconds.
Optionally provide a start time and jitter to adjust the
initial trigger and a random execution delay.

For example, a trigger that runs every 10 minutes
with a 20 second jitter:

	"interval": {
	 "minutes": 10,
	 "jitter": 20
	}

Interval Reference: [apscheduler.triggers.interval](https://apscheduler.readthedocs.io/en/3.x/modules/triggers/interval.html)


### Cron

The configured check is triggered
by UNIX cron style time fields (year,
month, day, hour, minute, second etc).
For example, to define a trigger
that is run at 5, 25 and 45 minutes past
the hour between 5am and 8pm every day:

	"cron": {
	 "hour": "5-20",
	 "minute": "5,25,45"
	}

Cron Reference: [apscheduler.triggers.cron](https://apscheduler.readthedocs.io/en/3.x/modules/triggers/cron.html)

