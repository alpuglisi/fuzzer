# BUG-0004 — App DB config defaulted to `root`, which modern MariaDB rejects

- Date: 2026-09-21
- Status: fixed
- Severity: medium

## Description
The lab app's `config/config.php` defaulted the database user to `root` with an
empty password (`getenv('PFF_DB_USER') ?: 'root'`). Modern MariaDB/MySQL
authenticates the `root` account via the unix socket (`unix_socket`/`auth_socket`
plugin), so a TCP login as `root` is refused regardless of the password supplied.
Whenever the `PFF_DB_*` environment variables were not provided — a manual LAMP
setup, PHP's built-in server, or any run where the env did not propagate — the app
fell back to `root` and failed to connect.

## Where encountered
Reported on review of `puppy-fort-factory/config/config.php` before pulling the repo
to run the on-host activities. The same failure was previously hit during the Fedora
deployment (`ERROR_LOG.md`, 2026-09-18, "Access denied for user 'root'").

## What it caused to fail
The app's shared `mysqli_connect` (`includes/db.php`) died with
`Database connection failed: Access denied for user 'root'@'localhost'`, so no page
could reach the database. Because it is the repo *default*, every fresh manual setup
reproduced it until the operator hand-edited `config.php`.

## What the bug was identified to be
A repo-committed default that selected an identity the target system does not accept,
and that also disagreed with the lab's own design: `lab/.env.example` and
`lab/compose.yaml` already define a dedicated least-privilege application user
(`pff`), and the containerized DB provisions it automatically. Only `config.php`'s
fallback still pointed at `root` (the single `root` literal in the app).

## Root cause analysis
Five Whys:
1. Why did the connection fail? The app authenticated as `root` over TCP.
2. Why `root`? `config.php` defaulted `DB_USER` to `root` when no env was set.
3. Why did that default survive, given the lab defines a `pff` user? The default was
   written before the containerized lab (`pff`) existed and was never reconciled with
   it.
4. Why wasn't it reconciled when the failure was first hit (2026-09-18)? That incident
   was resolved by an **out-of-repo workaround** (create `pff` locally, hand-edit
   `config.php`) and filed as `Status: Environment`, so the repo default was left
   broken.
5. Why does an "Environment" resolution leave a code bug? Because the environment fix
   does not change what the repo ships; the next person on a fresh checkout hits the
   same default.

**Root cause:** a committed credential/identity default (`root`) that neither the DBMS
accepts over TCP nor matches the lab's provisioned identity (`pff`), left unfixed
because the incident it caused was worked around only in the environment.

## Corrective action
- `config.php` now defaults `DB_USER`/`DB_PASS` to `pff` / `pff_lab_pw` (the
  documented lab credentials), never `root`; env vars still override, and a comment
  explains why root is avoided (socket auth + least privilege). `php -l` clean.
- App `README.md` manual setup now creates the least-privilege `pff` user (exact SQL)
  and stops pointing the app at `root`; the `schema.sql` import comment is aligned to
  `sudo mysql` (socket auth). Delivered as CC-LAB-0004.
- Swept the app for other `root` literals (PA-0002): the `config.php` default was the
  only one; the container path was already `pff` (compose env) and is unchanged.

## Preventive action
PA-0004 (see `docs/PREVENTIVE_ACTIONS.md`): a committed default that selects an
external identity/credential/endpoint must be one the target actually accepts **and**
must match what the lab provisions (compose / `.env` / schema); and when an incident
is resolved only by an environment workaround (an `ERROR_LOG` entry marked
`Environment`), still fix the repo default that led to it, so a fresh checkout does
not reproduce it.
