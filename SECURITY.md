# Security policy

## Safety boundaries

- `scan` is read-only except for writing its reports.
- `clean` requires `--yes`; database execution additionally requires both `--apply-sql` and `--yes-drop-tables`.
- Confirmed resources and injected files are quarantined outside the target. Edited files are backed up before replacement.
- The scanner reads text and metadata only. It never imports, executes or evaluates code from scanned FiveM resources.
- `server.cfg` credentials remain in process memory. Passwords are not printed, stored in reports, embedded in release assets or passed as a MySQL command-line argument.
- Multiple equally close `server.cfg` files with different database connections cause a hard failure instead of an automatic choice.
- Database operations are destructive and are not restored by the filesystem rollback command. Back up the database first.

## Release hygiene

The release builder rejects server configuration files, SQL dumps, scan reports, quarantine directories, caches and local build output. GitHub Releases include a SHA-256 checksum next to every ZIP.

## Reporting a vulnerability

Please open a private GitHub security advisory for credential exposure, unsafe path handling, unintended resource deletion or SQL scope issues. Do not include real database passwords or production `server.cfg` files in a public issue.
