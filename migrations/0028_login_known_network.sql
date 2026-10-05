-- ---------------------------------------------------------------------------
-- 0028: remember where a username signed in from (review)
-- ---------------------------------------------------------------------------
--
-- A username being guessed from many networks is backed off, except from the
-- networks it signed in from within 30 days (the owner's office, VPN or CI).
-- That memory was per instance and lost on restart: after a deploy during a
-- spray, the owner was backed off like the guesser. Successes are now
-- recorded here (at most hourly per network) and read only while the
-- username is being backed off. The username is stored as the SHA-256 of its
-- canonical form, the network as an IPv4 address or an IPv6 /64 prefix.
CREATE TABLE login_known_network (
    username_sha256 bytea       NOT NULL,
    network         text        NOT NULL,
    last_success_at timestamptz NOT NULL,
    PRIMARY KEY (username_sha256, network)
);

CREATE INDEX login_known_network_last_success_idx
    ON login_known_network (last_success_at);
