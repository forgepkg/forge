-- Docker / OCI registry (format `docker`): images, tags, blob links and
-- upload sessions.
--
-- An *image* is an OCI repository (`<name>` of `/v2/<name>/…`) inside a Forge
-- repository. Every byte (layers, configs, manifests, upload chunks) is a CAS
-- `blob`; the tables below only name blobs, and each row that names one holds
-- exactly one `blob.ref_count` reference, taken with
-- `blob_dao::commit_ingest_and_incref` / `commit_and_incref` in the
-- transaction that inserts the row and released with
-- `blob_dao::decref_and_maybe_enqueue_delete` in the one that deletes it:
--
--   * `oci_blob_link`   — a blob pushed, mounted or proxied into an image;
--   * `oci_manifest`    — a manifest's own bytes;
--   * `oci_upload_part` — a chunk of an upload session in progress.
--
-- A manifest does not hold references on its config and layers: they are
-- kept by the image's links, and the link sweeper drops only links that no
-- manifest of the same image names (`oci_manifest_ref`). A layer shared by
-- many images is one blob with one link (and one reference) per image.
--
-- `blob_dao`'s deletion guard counts the rows of all three tables (next to
-- `asset`), so a blob one of them names is never deleted even if its
-- `ref_count` drifted. None of them cascade from `blob`: the final
-- `DELETE FROM blob` fails while a row still names it.

CREATE TABLE oci_blob_link (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    -- `sha256:<hex>` or `sha512:<hex>`: the digest the blob was pushed as.
    digest        text        NOT NULL,
    blob_sha256   text        NOT NULL REFERENCES blob(sha256),
    size          bigint      NOT NULL CHECK (size >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Last pull/HEAD (bumped at most hourly); keeps a recently used link
    -- away from the sweeper while a manifest that names it is pushed.
    last_used_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, image, digest)
);

CREATE INDEX oci_blob_link_blob_idx ON oci_blob_link (blob_sha256);
CREATE INDEX oci_blob_link_sweep_idx ON oci_blob_link (last_used_at);

CREATE TABLE oci_manifest (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id   bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image           text        NOT NULL,
    digest          text        NOT NULL,
    blob_sha256     text        NOT NULL REFERENCES blob(sha256),
    media_type      text        NOT NULL,
    -- `artifactType`, else the config media type (what referrers report).
    artifact_type   text,
    -- The `subject` this manifest refers to (signatures, SBOMs, …).
    subject_digest  text,
    size            bigint      NOT NULL CHECK (size >= 0),
    -- Display data: platforms, layer total, annotations of a referrer.
    summary         jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- NULL while a tag points here; since when it has had none otherwise
    -- (retention's "untagged for X days").
    untagged_since  timestamptz,
    last_pulled_at  timestamptz,
    UNIQUE (repository_id, image, digest)
);

CREATE INDEX oci_manifest_blob_idx ON oci_manifest (blob_sha256);
CREATE INDEX oci_manifest_subject_idx
    ON oci_manifest (repository_id, image, subject_digest)
    WHERE subject_digest IS NOT NULL;

-- What a manifest names: its config and layers (`blob`) or, for an index,
-- its child manifests (`manifest`). Plain digests, no references held.
CREATE TABLE oci_manifest_ref (
    manifest_id bigint NOT NULL REFERENCES oci_manifest(id) ON DELETE CASCADE,
    kind        text   NOT NULL CHECK (kind IN ('blob', 'manifest')),
    digest      text   NOT NULL,
    PRIMARY KEY (manifest_id, kind, digest)
);

CREATE INDEX oci_manifest_ref_digest_idx ON oci_manifest_ref (digest, kind);

CREATE TABLE oci_tag (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    tag           text        NOT NULL,
    manifest_id   bigint      NOT NULL REFERENCES oci_manifest(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Proxy: when the tag was last confirmed against the upstream.
    checked_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, image, tag)
);

CREATE INDEX oci_tag_manifest_idx ON oci_tag (manifest_id);

-- A blob upload session (`POST /v2/<name>/blobs/uploads/`). Its chunks are
-- CAS blobs (`oci_upload_part`), so a session works across instances and a
-- single-chunk upload (what docker and containerd send) needs no second
-- copy: the chunk already is the blob.
CREATE TABLE oci_upload (
    id            uuid        PRIMARY KEY,
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    size          bigint      NOT NULL DEFAULT 0 CHECK (size >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oci_upload_updated_idx ON oci_upload (updated_at);

CREATE TABLE oci_upload_part (
    upload_id    uuid   NOT NULL REFERENCES oci_upload(id) ON DELETE CASCADE,
    seq          int    NOT NULL,
    start_offset bigint NOT NULL CHECK (start_offset >= 0),
    size         bigint NOT NULL CHECK (size > 0),
    blob_sha256  text   NOT NULL REFERENCES blob(sha256),
    -- The chunk's SHA-512 (standard base64), so a one-chunk upload pushed
    -- as `sha512:` is verified without reading the chunk back.
    sha512_base64 text  NOT NULL,
    PRIMARY KEY (upload_id, seq)
);

CREATE INDEX oci_upload_part_blob_idx ON oci_upload_part (blob_sha256);

-- Host-based routing: at most one docker repository per host name.
CREATE UNIQUE INDEX repository_docker_host_idx
    ON repository ((lower(config->>'host')))
    WHERE format = 'docker' AND config ? 'host';

-- Retention of images: tags and manifests are audited next to components.
ALTER TABLE retention_audit DROP CONSTRAINT retention_audit_action_check;
ALTER TABLE retention_audit
    ADD CONSTRAINT retention_audit_action_check
        CHECK (action IN ('unlist', 'hard_delete', 'skipped', 'delete_tag', 'delete_manifest'));
ALTER TABLE retention_audit DROP CONSTRAINT retention_audit_target_kind_check;
ALTER TABLE retention_audit
    ADD CONSTRAINT retention_audit_target_kind_check
        CHECK (target_kind IN ('component', 'proxy_cached_version', 'oci_tag', 'oci_manifest'));
