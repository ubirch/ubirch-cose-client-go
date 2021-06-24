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
RUN useradd \
    --home /home/cose-client --create-home \
    --uid 2000 cose-client
USER cose-client
COPY --from=builder app/main/main /opt/cose-client

# Add ultimaco library
ENV LD_LIBRARY_PATH=/usr/local/lib/ultimaco/
COPY hsm/libcs_pkcs11_R3.so /usr/local/lib/ultimaco/
# Example configuration
COPY hsm/cs_pkcs11_R3.cfg /etc/ultimaco/

ENTRYPOINT ["/opt/cose-client"]
CMD ["/data"]
