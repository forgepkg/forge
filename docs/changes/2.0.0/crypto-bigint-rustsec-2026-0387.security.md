The S3 client no longer compiles in SigV4a signing, and with it
`crypto-bigint` 0.5.5 (RUSTSEC-2026-0387): several of its operations meant
to run in constant time did not. The AWS SDK used it only to derive SigV4a
signing keys, which sign requests to AWS S3 Multi-Region Access Points (a
bucket given as an `arn:aws:s3::…:accesspoint/….mrap` ARN), a setup Forge
never documented or tested; requests to such a bucket now fail.
