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
ARG PESIEVE_VERSION="v0.3.5"
ARG PESIEVE_SHA256="ddb1292ad410895696b3606d76f0d8b968d88c78c42170c406e73484de5514e0"
RUN set -eux; \
    mkdir -p /opt/pesieve; \
    cd /opt/pesieve; \
    curl -fsSL -o pesieve.zip "https://github.com/hasherezade/pe-sieve/releases/download/${PESIEVE_VERSION}/pe-sieve64.zip"; \
    echo "${PESIEVE_SHA256}  pesieve.zip" > pesieve.sha256; \
    sha256sum --check pesieve.sha256; \
    unzip pesieve.zip; \
    rm pesieve.zip pesieve.sha256

RUN useradd -ms /bin/bash triage && mkdir -p /opt/triage && chown -R triage:triage /opt/triage /opt/pesieve
USER triage
WORKDIR /opt/triage

COPY triage.sh /opt/triage/triage.sh
ENTRYPOINT ["/bin/bash", "/opt/triage/triage.sh"]
