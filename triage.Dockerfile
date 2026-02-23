FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    WINEARCH=win64 \
    WINEDEBUG=-all

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wget curl unzip python3 python3-pip jq file \
        yara wine64 cabextract xvfb \
    && rm -rf /var/lib/apt/lists/*

# Install rizin static build (Ubuntu repositories may not provide a recent `rizin` package)
ARG RIZIN_VERSION="v0.8.2"
ARG RIZIN_SHA256="39299d492a43458900233e3036058b653d7554a6786192397fd4464c51fce5d6"
RUN set -eux; \
    curl -fsSL -o /tmp/rizin-static.tar.xz "https://github.com/rizinorg/rizin/releases/download/${RIZIN_VERSION}/rizin-${RIZIN_VERSION}-static-x86_64.tar.xz"; \
    echo "${RIZIN_SHA256}  /tmp/rizin-static.tar.xz" | sha256sum --check -; \
    tar -xf /tmp/rizin-static.tar.xz -C /tmp; \
    install -m 0755 /tmp/bin/rizin /usr/local/bin/rizin; \
    install -m 0755 /tmp/bin/rz-bin /usr/local/bin/rz-bin; \
    rm -rf /tmp/rizin-static.tar.xz /tmp/bin

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
