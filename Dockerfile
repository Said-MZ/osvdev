# syntax=docker/dockerfile:1
FROM ruby:3.3-alpine AS build

WORKDIR /app

RUN apk add --no-cache build-base

COPY Gemfile Gemfile.lock* stackwatch.gemspec ./
COPY lib/stackwatch.rb lib/

RUN bundle install --without development test --jobs 4 --retry 3

# --- runtime ---
FROM ruby:3.3-alpine AS runtime

WORKDIR /app

COPY --from=build /usr/local/bundle /usr/local/bundle
COPY . .

RUN chmod +x exe/stackwatch

ENV STACKWATCH_STATE_PATH=/data/state.json
VOLUME ["/data"]

ENTRYPOINT ["ruby", "exe/stackwatch"]
CMD ["run"]
