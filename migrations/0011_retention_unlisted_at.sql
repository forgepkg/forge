-- ---------------------------------------------------------------------------
-- When a version was unlisted (#185)
--
-- Retention's `unlisted_for_days` trigger deletes versions that have been
-- unlisted for N days (the second step of "unlist, then delete later"), so a
-- version records when it was unlisted: `component.unlisted_at`, NULL while
-- it is listed.
--
-- A trigger keeps it, so every path that unlists records it, whatever it is:
-- a client's unlist (NuGet's DELETE, npm), a retention run's `unlist`, a
-- push or import of a version that comes unlisted, a redeploy that unlists.
-- It is set when `listed` becomes false (or a row is inserted unlisted),
-- kept while the version stays unlisted (unlisting it again changes
-- nothing), and cleared when it is listed again. A write that sets
-- `unlisted_at` itself on an unlisted version keeps that value.
--
-- Versions unlisted before this migration take their `updated_at`: every
-- path that unlists a version sets `updated_at` to that moment, so it is
-- never earlier than the version was unlisted. A version changed again after
-- it was unlisted counts from that later change, which only defers its
-- deletion.
-- ---------------------------------------------------------------------------
ALTER TABLE component ADD COLUMN unlisted_at timestamptz NULL;

UPDATE component SET unlisted_at = updated_at WHERE NOT listed;

CREATE FUNCTION component_unlisted_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.listed THEN
        NEW.unlisted_at := NULL;
    ELSIF TG_OP = 'INSERT' OR OLD.listed THEN
        NEW.unlisted_at := COALESCE(NEW.unlisted_at, now());
    ELSE
        -- Still unlisted: it keeps the time it was unlisted, unless the write
        -- sets another one.
        NEW.unlisted_at := COALESCE(NEW.unlisted_at, OLD.unlisted_at, now());
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER component_unlisted_at
    BEFORE INSERT OR UPDATE OF listed, unlisted_at ON component
    FOR EACH ROW EXECUTE FUNCTION component_unlisted_at();
