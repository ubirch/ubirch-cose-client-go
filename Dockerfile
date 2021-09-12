ARG GOVERSION=1.16
FROM golang:$GOVERSION AS builder
COPY . /app
ARG GOARCH=amd64
ARG VERSION=devbuild
ARG REVISION=0000000
WORKDIR /app/main
RUN \
    GOPROXY=https://proxy.golang.org,direct \
    go build -trimpath -ldflags "-buildid= -s -w -X main.Version=$VERSION -X main.Revision=$REVISION" -o main .


FROM debian:bullseye
VOLUME /data
EXPOSE 8080/tcp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd \
    --home /home/cose-client --create-home \
    --uid 2000 cose-client
USER cose-client
COPY --from=builder app/main/main /opt/cose-client

# Add utimaco library
ENV LD_LIBRARY_PATH=/usr/local/lib/utimaco/
COPY hsm/libcs_pkcs11_R2.so /usr/local/lib/utimaco/
ENV CS_AUTH_KEYS=/etc/utimaco/HSMAuth.key
COPY hsm/HSMAuth.key /etc/utimaco/
ENV CS_PKCS11_R2_CFG=/etc/utimaco/cs_pkcs11_R2.cfg

ENTRYPOINT ["/opt/cose-client"]
CMD ["-configdirectory", "/data"]
