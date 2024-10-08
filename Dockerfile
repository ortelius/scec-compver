FROM cgr.dev/chainguard/go@sha256:a3b4696e85298d53baf4732d134894d951cdfd37f5c555d5efe0f5e9dce0f911 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:cabf47ee4e6e339b32a82cb84b6779e128bb9e1f2441b0d8883ffbf1f8b54dd2

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/docs docs

ENV ARANGO_HOST localhost
ENV ARANGO_USER root
ENV ARANGO_PASS rootpassword
ENV ARANGO_PORT 8529
ENV MS_PORT 8080

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
