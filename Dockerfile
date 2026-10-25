# syntax=docker/dockerfile:1

ARG RUUTTI_PLATFORM=linux/amd64

FROM --platform=$RUUTTI_PLATFORM alpine:3.20 AS builder
RUN apk add --no-cache build-base
WORKDIR /src
COPY Makefile ./
COPY src ./src
COPY tools ./tools
COPY third_party ./third_party
RUN make

FROM builder AS genhash
ENTRYPOINT ["/src/genhash"]

FROM --platform=$RUUTTI_PLATFORM scratch AS binary
COPY --from=builder /src/ruutti /ruutti

FROM --platform=$RUUTTI_PLATFORM alpine:3.20 AS runtime
RUN apk add --no-cache util-linux \
    && adduser -D -h /home/testi -s /bin/ash testi \
    && printf '%s\n' 'Welcome to ruutti' > /etc/motd \
    && printf '%s\n' 'export RUUTTI_LOGIN=1' > /etc/profile.d/ruutti.sh
COPY --from=builder /src/ruutti /usr/local/bin/ruutti
RUN chmod 4755 /usr/local/bin/ruutti
ENTRYPOINT ["/usr/local/bin/ruutti"]
