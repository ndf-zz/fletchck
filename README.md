# fletchck

Fletchck is a self-contained network service monitor.
It provides a suite of simple internet service
checks with flexible scheduling provided by
[APScheduler](https://apscheduler.readthedocs.io/en/master/)
and optional remote notification via MQTT.

Service checks trigger notification actions
as they transition from pass to fail or vice-versa.
Configuration is via JSON file or an in-built web
user interface.

The following checks are provided:

   - cert: Check TLS certificate validity or self-signed expiry
   - smtp: SMTP with optional starttls
   - submit: SMTP-over-SSL/Submissions
   - imap: IMAP4-SSL mailbox
   - https: HTTP/HTTPS request
   - ssh: SSH pre-auth connection with hostkey check
   - sequence: A sequence of checks, fails if any one member check fails
   - ups: Monitor a "QS" serial UPS status
   - upstest: Perform a "QS" serial UPS self-test and report faults
   - remote: Tracks the state of a check running on a remote instance
     fletchck over MQTT
   - disk: Disk space check, fails when usage exceeds percentage
   - memory: Check free memory space on host system
   - cpu: Check local average CPU load on host system
   - temp: Comet temperature probe
   - dns: DNS query

Service checks that use TLS will verify the service certificate
and hostname unless the selfsigned option is set.
If expiry of a self-signed certificate needs to be checked, use
the cert check with selfsigned option.

The following notification actions are supported:

   - email: Send an email
   - sms: Post SMS via Cloudkinnekt API
   - log: Log PASS/FAIL


## Installation

Create a python virtual env, and install from pypi using pip:

	$ python3 -m venv --system-site-packages venv
	$ ./venv/bin/pip3 install fletchck


## Setup

Create a new empty site configuration in the current
directory with the -init option:

	$ ./venv/bin/fletchck -init

Open a web browser with the displayed credentials to continue
setup.


## Configuration

Configuration is read from a JSON encoded dictionary
object with the following keys and values:

key | type | description
--- | --- | ---
base | str | Full path to location of site configuration file
timezone | str | Time zone for notifications, schedules and interface
webui | dict | Web user interface configuration (see Web UI below)
mqtt | dict | Persistent MQTT client connection (see MQTT below)
actions | dict | Notification actions (see Actions below)
checks | dict | Service checks (see Checks below)

Notes:

   - All toplevel keys are optional
   - If webui is not present or null, the web user interface
     will not be started.
   - If mqtt is not present or null, the MQTT client is not started.
   - Action and check names may be any string that can be used
     as a dictionary key and that can be serialised in JSON.
   - Duplicate action and check names will overwrite earlier
     definitions with the same name.
   - Timezone should be a zoneinfo key or null to use host localtime


### Actions

Each key in the actions dictionary names a notification
action dictionary with the following keys and values:

key | type | description
--- | --- | ---
type | str | Action type, one of 'log', 'email' or 'sms'
options | dict | Dictionary of option names and values

The following action options are recognised:

option | type | description
--- | --- | ---
hostname | str | Email submission hostname
url | str | API Url for SMS sending
port | int | TCP port for email submission
username | str | Username for authentication
password | str | Password for authentication
sender | str | Sender string
timeout | int | TCP timeout for email submission
recipients | list | List of recipient strings
site | str | Site identifier (default is Fletchck)


### Checks

Each key in the checks dictionary names a service check
with the following keys and values:

key | type | description
--- | --- | ---
type | str | Check type: cert, smtp, submit, imap, https, ssh, remote, disk, ups, upstest or sequence
subType | str | Optional subtype, set on update for remote checks
trigger | dict | Trigger definition (see Scheduling below)
threshold | int | Fail state reported after this many failed checks
failAction | bool | Send notification action on transition to fail
passAction | bool | Send notification action on transition to pass
publish | str | MQTT topic to log check state to
remoteId | str | Name of remote check if different to local check name
options | dict | Dictionary of option names and values (see below)
actions | list | List of notification action names
depends | list | List of check names this check depends on
data | dict | Runtime data and logs (internal)

Note that only the type is required, all other keys are optional.
The following check options are recognised:

option | type | description
--- | --- | ---
hostname | str | Hostname or IP address of target service
port | int | TCP port of target service
timeout | int | Timeout in seconds
timezone | str | Timezone for schedule and notification
selfsigned | bool | If set, TLS sessions will not validate service certificate
tls | bool | (smtp) If set, call starttls to initiate TLS
probe | str | (cert) send str probe to service after TLS negotiation
reqType | str | (https/dns) Request method: HEAD, GET, POST, TXT, SOA, AAAA, etc
reqPath | str | (https) Request target resource
reqName | str | (dns) Name to request from dns server
reqTcp | bool | (dns) If true, use TCP
hostkey | str | (ssh) Target service base64 encoded public key
checks| list | (sequence) List of check names to be run in-turn
volume | str | (disk) Path of disk volume to be checked
level | int | (disk) Disk space failure percentage
serialPort | str | (ups*) Serial port to use for UPS communication

Unrecognised options are ignored by checks.

Example:

	"checks": {
	 "Home Cert": {
	  "type": "cert",
	  "passAction": false,
	  "trigger": { "cron": {"day": 1, "hour": 1} },
	  "options": { "hostname": "home.place.com", "port": 8443 },
	  "actions": [ "Tell Alice" ]
	 }
	}

Define a single check named "Home Cert" which performs
a certificate verification check on port 8443 of
"home.place.com" at 1:00 am on the first of each month,
and notifies using the action named "Tell Alice" on
transition to fail.


## Scheduling

Job scheduling is managed by APScheduler. Each defined
check may have one optional trigger of type interval or cron.

Within the web interface, trigger schedules are entered
using a plain text whitespace separated list of value/unit pairs.

An interval trigger with an explicit start:

	interval 1 week 2 day 3 hr 5 min 15 sec

A cron trigger with an explicit timezone:

	cron 9-17 hr 20,40 min mon-fri weekday Australia/Adelaide z


### Interval

The check is scheduled to be run at a repeating interval
of the specified number of weeks, days, hours, minutes
and seconds.

For example, a trigger that runs every 10 minutes:

	"interval": {
	 "minutes": 10
	}

Interval reference: [apscheduler.triggers.interval](https://apscheduler.readthedocs.io/en/3.x/modules/triggers/interval.html)


### Cron

The configured check is triggered by UNIX cron style
time fields (year, month, day, hour, minute, second etc).
For example, to define a trigger that is run at 5, 25
and 45 minutes past the hour between 5am and 8pm every day:

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
cert | str | path to TLS certificate
key | str | path to TLS private key
host | str | hostname to listen on
port | int | port to listen on
name | str | site name displayed on header
base | str | path to configuration file
users | dict | authorised usernames and hashed passwords


## MQTT

The fletchck instance can be configured to maintain a persistent
MQTT connection using the mqtt configuration object:

key | type | description
--- | --- | ---
hostname | str | MQTT broker hostname or IP
port | int | MQTT broker port
tls | bool | Use TLS for client connection
username | str | Login username
password | str | Login password
clientid | str | Client id for persistent connection (None for automatic)
persist | bool | Use a persistent connection (default: True)
qos | int | QoS for publish and subscribe (default: 1 "at least once")
retain | bool | Publish check updates with retain flag (default: True)
basetopic | str | Topic to receive remote updates
autoadd | bool | Automatically add remote checks on reception of update message
debug | bool | Include debugging information on MQTT client

Checks are configured to report to MQTT by entering a topic
in the "publish" option. Reception of valid notifications
to the configured "basetopic" option (which may include a trailing
wildcard) will trigger update of the remote check state.

To monitor a remote check for lack of update, add an interval
or cron trigger to the remote entry and edit the timeout time
to set an update expiry.

