# Changelog

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
