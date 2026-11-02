-- ---------------------------------------------------------------------------
-- Imports of apt repositories (#644)
--
-- An import copies an apt repository's binary packages into a hosted apt
-- repository. The source is a repository's base URL (`url`) and one of its
-- distributions; its `Release` names every `Packages` index, which lists
-- every `.deb` with its size and SHA-256.
--
-- * `distribution`: the source's distribution (`bookworm`), whose
--   `dists/<distribution>/InRelease` (or `Release`) the scan reads.
-- * `public_key`: the source's OpenPGP public keys, ASCII-armored, when the
--   import was given them: its `Release` must then carry a valid signature
--   of one of them. Public, so stored as it is.
-- * `scan_listing` takes `release`: the scan walks the indexes `Release`
--   names, its cursor `<component>/<architecture>` of the index it is in
--   and the entries of it recorded already.
-- ---------------------------------------------------------------------------
ALTER TABLE repository_import ADD COLUMN distribution text;
ALTER TABLE repository_import ADD COLUMN public_key text;

ALTER TABLE repository_import DROP CONSTRAINT repository_import_scan_listing_check;
ALTER TABLE repository_import ADD CONSTRAINT repository_import_scan_listing_check
    CHECK (scan_listing IN ('search', 'catalog', 'all', 'assets', 'directories', 'release', 'names'));
