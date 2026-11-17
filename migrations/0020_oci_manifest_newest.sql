-- ---------------------------------------------------------------------------
-- An image's newest manifests, without reading the whole image (#561)
--
-- The image page lists at most the newest 1,000 tags and 1,000 manifests of
-- an image (#240), but found them by reading every manifest and tag of it:
-- no index knows a manifest's age. This one lists an image's manifests
-- newest first, so the page reads the ones it shows.
-- ---------------------------------------------------------------------------
CREATE INDEX oci_manifest_newest_idx
    ON oci_manifest (repository_id, image, created_at DESC, digest);
