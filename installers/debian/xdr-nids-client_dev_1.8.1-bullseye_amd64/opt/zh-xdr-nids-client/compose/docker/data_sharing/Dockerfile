FROM fluentd:v1.16.0-debian-1.0

USER root
COPY dist/entrypoint.sh /bin/
RUN apt update && \
    apt upgrade -y && \
    apt install ruby-dev build-essential libgeoip-dev libmaxminddb-dev curl bzip2 aria2 autoconf libtool -y && \
    mkdir -p /etc/listbot && \
    gem install geoip2_c && \
    fluent-gem install fluent-plugin-opensearch --no-document && \
    fluent-gem install fluent-plugin-record-modifier --no-document && \
    fluent-gem install fluent-plugin-geoip --no-document && \
    fluent-gem install fluent-plugin-dict-map --no-document && \
    fluent-gem install fluent-plugin-dedot_filter --no-document && \
    fluent-gem install fluent-plugin-s3 --no-document && \
    apt autopurge build-essential ruby-dev -y && \
    gem sources --clear-all  && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* /var/tmp/* /usr/lib/ruby/gems/*/cache/*.gem && \
    chown -R fluent:fluent /etc/listbot && \
    chmod +x /bin/entrypoint.sh && \
    mkdir -p /var/log/zerohack/gluon


COPY dist/geo-data /geo-data
COPY dist/fluent.conf /fluentd/etc/fluent.conf
