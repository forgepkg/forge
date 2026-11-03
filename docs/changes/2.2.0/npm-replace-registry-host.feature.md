An npm proxy or group can offer
`npm config set replace-registry-host <package-lock.json-host>` in its
**Connect** panel in the web UI, which has npm download the tarballs of a
`package-lock.json` written against another registry through the repository
instead. It is off by default: an administrator switches on **Show npm's
replace-registry-host setting** in the repository's settings (admin API:
the option `show_replace_registry_host`). A format option can now be such a
switch (`OptionInput::Switch`).
