The guides were brought in line with the code. [CI with service
accounts](docs/ci-service-accounts.md) gives the CI accounts **Roles only**,
not **Reader**, which reads every repository. The [NuGet guide](docs/nuget.md)
pushes and unlists through a source of the hosted repository, since a group
takes no NuGet pushes. DEVELOPMENT.md lists the root key of the secret
encryption among the settings a server needs to start. The README and the
format-plugin guide describe every format as a plugin built into the server,
not a preview of further formats, and the format lists name apt and npm
where they were missing.
