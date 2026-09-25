# Target-lab web tier: Ruby on Rails serving the generated `ruby_rails`
# (ForgeCart) lab app. CC-LAB-0247 (Lane 7, §2b). Two stages: `gen` runs the
# real generator (`fuzzlab.labgen.emitters.ruby_rails.assemble_ruby_rails_app`,
# the same assembly `RailsLiveBootHarness._assemble()` uses -- PA-0027) to
# produce the Rails app tree; the real stage installs the pinned Ruby/Gemfile
# dependencies and serves it for real via `lab/docker-entrypoint-rails.sh`
# (D12: `SECRET_KEY_BASE` generated fresh at container start, never baked in
# or committed).
#
# Build context is the REPO ROOT (`lab/compose.yaml`'s `build.context: ..`).

FROM docker.io/library/python:3.12-slim AS gen
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -c "from fuzzlab.labgen.emitters.ruby_rails import assemble_ruby_rails_app; assemble_ruby_rails_app('/app')"

# .ruby-version pins `ruby-3.3.6` -- matches this stage's tag exactly.
FROM docker.io/library/ruby:3.3.6-bookworm
WORKDIR /app
COPY --from=gen /app /app
RUN bundle install
COPY lab/docker-entrypoint-rails.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/docker-entrypoint.sh"]
