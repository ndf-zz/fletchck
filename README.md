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

## Configuration

Configuration is read from a JSON encoded dict object
with the following keys and values:

key | type | description
--- | --- | ---
webui | dict | Web user interface configuration (see Web UI below)
actions | dict | Notification actions (see Actions below)
checks | dict | Service checks (see Checks below)

### Actions

Each key in the actions dict names a notification
action dict with the following keys and values:

key | type | description
--- | --- | ---
type | str | Action type, one of 'log', 'email' or 'sms'
options | dict | Dictionary of option names and values

The following action options are recognised:

option | type | actions | description
--- | --- | --- | ---
hostname | str | email,sms | Hostname to use for sending notification
port | int | email | TCP port for email submission
username | str | email,sms | Username for authentication
password | str | email,sms | Password for authentication
sender | str | email,sms | Sender string
timeout | int | email | TCP timeout for email submission
recipients | list | email | List of email recipient strings
recipient | str | sms | Recipient phone number

Notes:

   - The log action does not recognise any options

### Checks

Each key in the checks dict names a service check
with the following keys and values:

key | type | description
--- | --- | ---
type | str | Check type, one of 'cert', 'smtp', 'submit', 'imap', 'https', 'ssh' or 'sequence'
trigger | dict | Trigger definition (see Scheduling below)
threshold | int | Fail state reported after this many failed checks
failAction | bool | Send a notification action on transision to fail
passAction | bool | Send a notification action on transition to pass
options | dict | Dictionary of option names and values
actions | list | List of notification action names
depends | list | List of check names that this check depends on
data | dict | Runtime data and logs (internal)

Note that only the type is required, all other keys are optional.
The following check options are recognised:

TODO

option | type | checks | description
--- | --- | --- | ---

### Example

The follwing configuration might describe a setup with no
web ui that runs a set of checks for a single
site with a web site and SMTP, IMAP services behind a router.
Router connectivity is checked every 5 minutes while
the other services are checked in a sequence once per hour
during the day. Failures of the router will trigger
an sms, while service failures send an email.

	{
	 "webui": null,
	 "actions": {
	  "sms-admin": {
	   "type": "sms",
	   "options": { "recipient": "+1234234234" }
	  },
	  "email-all": {
	   "type": "email",
	   "options": {
	    "hostname": "mail.place.com",
	    "sender": "monitor@place.com",
	    "recipients": [ "admin@place.com", "info@place.com" ]
	   }
	  }
	 },
	 "checks": {
	  "place-gateway": {
	   "type": "ssh",
	   "trigger": { "interval": { "minutes": 5 } },
	   "options": { "hostname": "gw.place.com" },
	   "actions": [ "sms-admin" ]
	  },
	  "place-svc": {
	   "type": "sequence",
	   "trigger": { "cron": { "hour": "9-17", "minute": "0" } },
	   "options": { "checks": [ "place-email", "place-mbox", "place-web" ] },
	   "actions": [ "email-all" ]
	  },
	  "place-email": {
	   "type": "smtp",
	   "options": { "hostname": "mail.place.com" },
	   "depends": [ "place-gateway" ]
	  },
	  "place-mbox": {
	   "type": "imap",
	   "options": { "hostname": "mail.place.com" },
	   "depends": [ "place-gateway" ]
	  },
	  "place-web": {
	   "type": "https",
	   "options": { "hostname": "place.com" }
	  }
	 }
	}

## Scheduling

Job scheduling is managed by APScheduler. Each defined
check may have one optional trigger of type interval or cron.

### Interval

The check is scheduled to be run at a repeating interval
of the specified number of weeks, days, hours, minutes
and seconds. Optionally provide a start time and jitter
to adjust the initial trigger and a random execution delay.

For example, a trigger that runs every 10 minutes
with a 20 second jitter:

	"interval": {
	 "minutes": 10,
	 "jitter": 20
	}

Interval reference: [apscheduler.triggers.interval](https://apscheduler.readthedocs.io/en/3.x/modules/triggers/interval.html)

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

Cron reference: [apscheduler.triggers.cron](https://apscheduler.readthedocs.io/en/3.x/modules/triggers/cron.html)

## Web UI

The web user interface is configured with the webui key 
of the site config. The keys and values are as follows:

key | type | description
--- | --- | ---
debug | bool | Include debugging information on web interface
cert | str | path to TLS certificate
key | str | path to TLS private key
host | str | hostname to listen on
port | int | port to listen on
name | str | site name displayed on header
base | str | path to configuration file
users | dict | authorised usernames and hashed passwords
