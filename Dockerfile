FROM cgr.dev/chainguard/go@sha256:395ba0e04ecfdb3dc6f27b3dd8cac43fa8ccbf41618ee3ccfc8fc3d431750778 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:ed3619242595eb5177a3bdae804d113401e37315d2cddba97eeeb4d038560821

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
