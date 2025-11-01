FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    WINEARCH=win64 \
    WINEDEBUG=-all

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wget curl unzip python3 python3-pip jq file \
        yara wine64 cabextract xvfb \
        rizin \
    && rm -rf /var/lib/apt/lists/*

# Install pe-sieve (latest stable)
RUN mkdir -p /opt/pesieve && \
    cd /opt/pesieve && \
    curl -L -o pesieve.zip https://github.com/hasherezade/pe-sieve/releases/download/0.3.5/pe-sieve64.zip && \
    unzip pesieve.zip && \
    rm pesieve.zip

RUN useradd -ms /bin/bash triage && mkdir -p /opt/triage && chown -R triage:triage /opt/triage /opt/pesieve
USER triage
WORKDIR /opt/triage

COPY triage.sh /opt/triage/triage.sh
ENTRYPOINT ["/bin/bash", "/opt/triage/triage.sh"]
