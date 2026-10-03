-- ---------------------------------------------------------------------------
-- 0029: let a group name the members that own package ids (review)
-- ---------------------------------------------------------------------------
--
-- A group trusted every hosted member equally: anyone who could push to any
-- hosted member could publish under the group's reserved prefixes, and with
-- prefer_hosted claim any public package id for the whole group (its proxied
-- versions then stopped being served). Once at least one member of a group is
-- flagged `owner`, only flagged members (and the hosted repositories inside a
-- flagged nested group) own ids there: they alone hide proxy versions under
-- prefer_hosted, and they alone serve ids under reserved prefixes. Groups
-- without a flagged member keep the old behaviour.
ALTER TABLE group_member
    ADD COLUMN owner boolean NOT NULL DEFAULT false;
