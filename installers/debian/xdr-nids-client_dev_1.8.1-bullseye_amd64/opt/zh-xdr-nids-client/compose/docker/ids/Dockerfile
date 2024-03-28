FROM alpine:3.19

# Include dist
ADD dist/ /root/dist/

# Install packages
RUN apk update && \
    apk upgrade && \
    apk -U --no-cache add ca-certificates curl file hiredis libcap wget suricata=7.0.2-r0 lua5.3-dev outils-md5 build-base unzip && \
    # Setup user, groups and configs
    addgroup -g 2000 suri && \
    adduser -S -H -u 2000 -D -g 2000 suri && \
    chmod 644 /etc/suricata/*.config && \
    cp /root/dist/*.yaml /etc/suricata/ && \
    cp /root/dist/*.conf /etc/suricata/ && \
    cp /root/dist/*.bpf /etc/suricata/ && \
    cp /root/dist/*.sh . && \
    cp /root/dist/update.sh /usr/bin/ && \
    chmod 755 /usr/bin/update.sh && \
    # Clean up
    rm -rf /root/* && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/apk/*

# Start suricata
STOPSIGNAL SIGINT

CMD SURICATA_CAPTURE_FILTER=$(update.sh OPEN) && exec suricata -v -F $SURICATA_CAPTURE_FILTER -i $PREFERRED_INT 
