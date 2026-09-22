# `ruby_rails` `stack/` provenance

Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §2/§9.4a/§9.5 (category 1
e-commerce pilot, Shopify's Ruby-on-Rails stack) -- this project's first
Ruby-on-Rails stack, built as the direct port of `php_laravel/stack/`'s own
proven pattern (see that directory's `README.md`).

## Ruby / Rails / Bundler versions actually resolved (not guessed)

Verified against a real `rubygems.org` round trip on 2026-09-22
(`gem query -r -n "^rails$" --all`), the current stable Rails release was
**8.1.3.1**, not the `7.x` this task's own dispatch instructions guessed
before verification -- the instructions themselves say "don't guess a
version... pick a real, current stable release", which this resolves in
favor of what is actually current on rubygems.org today, not the guess.
Rails moves fast enough that a plan written even a few months earlier no
longer names the current major; nothing in this dispatch's scope depends on
Rails 7 specifically.

- **Ruby**: `3.3.6` (already on `PATH` in this sandbox; confirmed, not
  assumed).
- **RubyGems**: `3.5.22`.
- **Bundler**: `4.0.9` (whatever `gem install rails` pulled in as a
  dependency; not pinned to an older version).
- **Rails**: `8.1.3.1` (`gem install rails -v 8.1.3.1`, and pinned in
  `skeleton/Gemfile` as `gem "rails", "~> 8.1.3", ">= 8.1.3.1"` -- the exact
  constraint `rails new` itself writes).

## `skeleton/` (`CC-LAB-0071`/`FR-LAB-65`, 2026-09-22)

The real, minimal, **bootable** Rails 8.1 project skeleton the live-boot
conformance harness (`fuzzlab/labgen/conformance/rails_live_boot.py`)
overlays a manifest's generated content onto -- the Rails equivalent of
`php_laravel/stack/skeleton/`.

**Provenance.** A real, un-doctored `rails new fuzzlab_app --minimal
--skip-git --skip-bundle --skip-test --skip-system-test --skip-ci` run in a
scratch directory (2026-09-22, same RubyGems access this directory's own
`Gemfile.lock` was resolved against: `bundle install` from the generated
project, real Rails `8.1.3.1`, `sqlite3 2.9.6`, `puma 8.0.2`, `propshaft
1.3.2`, 69 gems total). `--minimal` is Rails' own generator flag (not a
manual trim) and already excludes ActiveStorage, ActionCable/ActionMailbox/
ActionMailer, Solid Cache/Queue/Cable, Kamal deploy config, Hotwire/Turbo/
Stimulus, and the JS/CSS build pipeline -- none of which any Phase A or
currently-planned Phase B cell needs. SQLite is the generator's own
`--minimal` default database (`config/database.yml`), matching this stack's
per-run-database story below with zero extra configuration -- unlike
`php_laravel`, where SQLite required overriding the real lab's own MySQL
`.env` default.

**Trim list, applied on top of the real `rails new --minimal` output**
(mirroring `php_laravel/stack/README.md`'s own trim-list convention):

- `.git/` (generator artifact, never carried; this repo's own git tracks the
  skeleton instead).
- `bin/ci` + `config/ci.rb` -- Rails 8's built-in CI-runner scaffold
  (`ActiveSupport::ContinuousIntegration`), dev/CI-only tooling with no role
  in a live-boot harness, the same category `php_laravel` strips its
  `.github/` workflow templates for.
- `bin/dev` -- a one-line `exec bin/rails server` wrapper; the harness
  invokes `bin/rails server` directly, so this indirection is unused.
- `config/master.key` + `config/credentials.yml.enc` -- Rails' encrypted
  credentials store and its secret decryption key. Never checked in for the
  same reason `php_laravel`'s skeleton carries no `.env`/`.env.example`: a
  live-boot harness generates its own real `SECRET_KEY_BASE` per run (see
  `rails_live_boot.py`), and nothing this stack's Phase A/planned Phase B
  cells need lives in encrypted credentials.
- `public/icon.png` (binary, cosmetic, 512x512 PNG) -- `public/icon.svg`
  (122 bytes, text) is kept and the generated layout's `<link>` tags were
  edited to reference only the SVG, the same "binary/cosmetic asset not
  carried" rule `php_laravel` applies to `public/favicon.ico`.
- `config/routes.rb` -- not carried, exactly like `php_laravel` does not
  carry `routes/web.php`: the harness overlays its own, assembled from a
  manifest's `RailsEmitter.route_fragment_for()` fragments via
  `RouteAccumulator` (see `rails_live_boot.py`'s `_assemble()`).
- Runtime-generated artifacts never meaningful to check in: `storage/
  development.sqlite3`, `log/development.log`, `tmp/restart.txt`,
  `tmp/cache/`, `tmp/sockets/` (the generator creates these as a side effect
  of an interactive `rails new`/first boot, not as project source; `.keep`
  placeholders are kept wherever a directory itself must exist for Rails'
  own boot-time `mkdir`-on-demand assumptions to hold, e.g. `log/.keep`,
  `tmp/pids/.keep`, `storage/.keep`, `tmp/storage/.keep`).

**No `tests/`/`test/` directory existed to strip** (`--skip-test
--skip-system-test`): this project's own test suite covers the harness,
matching `php_laravel`'s own reasoning for not carrying Laravel's scaffolded
PHPUnit stubs.

**Scope**: this skeleton is a test-harness / conformance-check asset, per
this dispatch's own explicit boundary (Phase A only) -- it is not wired into
`lab/compose.yaml`/`deploy.sh`, and `lab/safety_matrix.yaml` is untouched.
