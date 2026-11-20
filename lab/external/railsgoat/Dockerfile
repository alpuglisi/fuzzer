# OWASP RailsGoat at the pinned commit (held out: lab/HOLDOUT.md). Lab-only, loopback-only.
# `python -m fuzzlab.lab_fixtures.external fetch railsgoat` checked the source out at
# RAILSGOAT_COMMIT (its files hashed against RAILSGOAT_TREE_SHA256) and downloaded every
# gem its Gemfile.lock pins for this platform into .cache/app/vendor/cache (each checked
# against the lock's CHECKSUMS sha256), plus the bundler the lock names (BUNDLED WITH
# 4.0.4, checked against rubygems.org's sha256). The build installs them with no network
# (compose: build.network none) and fetches nothing.
FROM mirror.gcr.io/library/ruby:3.4.1@sha256:f78dc1bba60f85d40d6dc6d6722ca2cda0b5273fc179119badd0f7654d5d1d6e
COPY .cache/bundler/bundler-4.0.4.gem /tmp/bundler-4.0.4.gem
RUN gem install --local --no-document /tmp/bundler-4.0.4.gem && rm /tmp/bundler-4.0.4.gem
COPY .cache/app /app
WORKDIR /app
# upstream runs `rails s` in development (its database.yml's sqlite3 development DB);
# the development/test/mysql/openshift groups (debuggers, livereload, test tooling,
# other databases) are not installed; Bundler.require then skips them
ENV RAILS_ENV=development \
    BUNDLE_WITHOUT=development:test:mysql:openshift \
    BUNDLE_FROZEN=true \
    DATABASE_URL=sqlite3:/data/development.sqlite3 \
    SKIP_TEST_DATABASE=true \
    HOME=/tmp
RUN bundle install --local --jobs 4 && rm -rf vendor/cache \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin railsgoat
USER railsgoat
# a fresh database at every start (the tmpfs /data is empty): upstream's README says
# `rails db:setup` (schema load + db/seeds.rb: the metacorp.com accounts)
CMD ["sh", "-c", "bundle exec rails db:setup && exec bundle exec rails server -b 0.0.0.0 -p 3000"]
