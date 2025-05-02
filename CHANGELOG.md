# Changelog

## [1.1.2] 2025-05-02

### Added

   - NUT UPS client check
   - Icon option for sms and email actions

### Changed

   - Suppress apsched INFO logs
   - Suppress paramiko INFO logs
   - Prune volatile log around 100 entries

### Removed

   - QS serial UPS checks

### Fixed

   - Allow sms config without API key
   - Fix import to empty config
   - Fix typo in webui timezone lookup


## [1.1.1] 2025-02-01

### Added

### Changed

### Deprecated

### Removed

### Fixed

  - Pass temporary web and mqtt config handles to form when editing
  - Create default mqtt config when enabled from web interface
  - Require port to be specified on web interface config
  - Link UTC to datetime.timezone.utc for Python < 3.11

### Security


## [1.1.0] 2025-01-31

### Added

  - Add landing page in webui with summary of failing checks
  - Add facility to reorder checks and sequences from listing page
  - Add CPU and RAM checks using psutil library
  - Add check clone function on listing page
  - Pause check feature
  - Site configuration edit in webui
  - Add/remove/edit actions
  - Add/remove/edit users
  - Display next run time for checks with triggers in list and edit pages
  - Add option to merge existing config into site at startup
  - Add option to import check data from CSV on startup
  - Convert hostname MAC address to ipv6 LL address
  - Append scope 2 to unscoped LL ipv6 address

### Changed

  - Replace actions top menu item with site config
  - Hide retries option on sequence and remote checks
  - Alow override of web UI port on command line
  - Don't add dummy action during site --init
  - Group checks under sequences in check listing
  - Exclude failing sequences from count of failing checks
  - Log only last attempt when retries > 1
  - Include level in sequence logs for passing checks
  - Update bootstrap to v5.3.3
  - Update bootstrap icons to v1.11.3
  - Remove direct priority editing from check editor
  - Allow optional TLS on https checks
  - Create check hides all options until name and type are entered
  - Sequence membership may be edited from check
  - Clear retained topic when remote check deleted
  - Use site-wide jitter from defaults for all defined triggers
  - Interval triggers are scheduled to fire immediately after edit

### Deprecated

### Removed

  - Smscentral apiSms action type
  - Mqtt one-shot publish action type
  - Trigger options jitter and start_date
  - Hard-coded email and sms actions editor

### Fixed

  - Create copy of options when flattening check
    instead of using reference

### Security


## [1.0.7] 2025-01-10

### Added

  - Add new check type 'dns' to query nameserver operation
  - Allow change of name on remote check entries

### Changed

### Deprecated

### Removed

### Fixed

### Security


## [1.0.6] 2024-11-29

### Added

  - Add new action type for Cloudkinnect SMS API
  - Add new check 'temp' to query temperature of comet poe thermometer

### Changed

  - Retry failing checks 'retries' times before flagging failed state
  - Change notification icon from poo to dog
  - Include 'level' stat for checks where that makes sense (disk,temp)
  - Adjust sequence summary to show softfail checks with "no entry"
  - Simplify logs and summaries

### Deprecated

### Removed

### Fixed

   - Fix unhandled JSON object decode error for remote messages
   - Fix invalid property on disk check exception

### Security

   - Add strict checking on remote data validation

## [1.0.5] 2024-07-29

### Added

   - Changelog based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
   - Mqtt action for single-fire notifications to mqtt
   - Mqtt client library for remote action monitoring
   - Remote check type with mqtt updates
   - Disk space check 
   - Publish option for mqtt monitoring

### Changed

   - Alter sms formatting for easier reading
   - Alter ssh check to save host key on first run
   - BaseCheck includes a subType for remote checks

### Deprecated

### Removed

### Fixed

   - Sequence fail state ordering corrected to match priority
   - Fix minor logic issues in actions
   - Set fail state before running quit command to avoid false positive
     in imap and smtp checks to servers that drop connections before
     fully replying

### Security


## [1.0.4] - 2024-01-04

### Changed

   - Failstate for checks may be any type, not just boolean
   - Notify on change of fail state, not just truth value
   - Set sequence fail state based on which units are failing
   - Use create_connection for TCP sockets so IPv6 addrs may be entered
   - Suppress self from lists of available dependencies and sequence items
   - Replace option/select form elements with select buttons

### Added

   - Basic serial UPS checks (Ninja/QsV)
   - Provide a fallback "sendmail" emailer if available on the host system

### Fixed

   - Fix typo and id errors on html form elements

## [1.0.3] - 2023-10-30

### Changed

   - Log failing checks as WARNING

### Fixed

   - Fix timestamp in email notifications
   - Fix typo in manual email test

## [1.0.1] - 2023-10-25

### Added

   - Granular timezone support
   - Add priority field to options for ordering

### Fixed

   - Fix typo on certificate expiry check
   - Correct option names for https check

## [1.0.0] - 2023-10-22

Initial Release, basic application outline with working
scheduler and user interface.
