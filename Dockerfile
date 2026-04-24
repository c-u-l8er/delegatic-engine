# Build stage ────────────────────────────────────────────
FROM elixir:1.18-slim AS build

RUN apt-get update -y && apt-get install -y build-essential git curl && apt-get clean

WORKDIR /app

RUN mix local.hex --force && mix local.rebar --force

ENV MIX_ENV=prod

# anubis_mcp is vendored in ../graphonomous/vendor. The Dockerfile
# expects the build context to be the ProjectAmp2 root so the
# relative path dep resolves correctly.
#
#   docker build -f delegatic/Dockerfile -t delegatic .
#   flyctl deploy --dockerfile delegatic/Dockerfile .

COPY delegatic/mix.exs delegatic/mix.lock ./
COPY graphonomous/vendor/anubis_mcp ../graphonomous/vendor/anubis_mcp

RUN mix deps.get --only $MIX_ENV
RUN mix deps.compile

COPY delegatic/lib lib

RUN mix compile
RUN mix release

# Runtime stage ──────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update -y && \
    apt-get install -y libstdc++6 openssl libncurses6 libtinfo6 locales ca-certificates && \
    apt-get clean && rm -f /var/lib/apt/lists/*_*

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8

WORKDIR /app
RUN chown nobody /app

COPY --from=build --chown=nobody:root /app/_build/prod/rel/delegatic ./

USER nobody

CMD ["bin/delegatic", "start"]
