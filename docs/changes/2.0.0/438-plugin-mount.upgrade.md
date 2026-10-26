The plugin API no longer includes a URL `mount` in a format's `Descriptor`.
Update custom format implementations to remove that field; repositories are
served under `/repository/<name>/` regardless of format.
