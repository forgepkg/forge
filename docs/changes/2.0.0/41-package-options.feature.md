Hosted NuGet repositories have a deployment policy, like raw and npm ones:
allow redeploys, refuse them (the default), or read-only, which refuses
every push, unlist and delete. `allow_redeploy` says the same and follows
it. A NuGet group may have a writable member, a hosted member that pushes,
unlists and deletes through the group go to. The web UI's repository form
offers both.
