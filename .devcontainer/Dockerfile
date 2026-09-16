# Ubuntu 26.04 LTS ships OpenSSL 3.5.x in the base archive, so the hybrid
# groups this project depends on (X25519MLKEM768, SecP256r1MLKEM768,
# SecP384r1MLKEM1024) are available from apt with no source build.
#
# Do NOT drop this to 24.04: that ships OpenSSL 3.0, which cannot offer any
# ML-KEM group. The scanner detects this and refuses rather than reporting
# targets as lacking support, but you lose the ability to test anything real.
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv \
        git \
        shellcheck \
        curl \
        less \
        dnsutils \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Fail the image build early if the base ever moves off 3.5..
RUN openssl version | grep -qE 'OpenSSL 3\.(5|[6-9]|[1-9][0-9])' \
    || (echo "FATAL: base image OpenSSL is $(openssl version), need 3.5+" && exit 1)

ARG USERNAME=vscode
RUN useradd -m -s /bin/bash ${USERNAME} \
    && apt-get update \
    && apt-get install -y --no-install-recommends sudo \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && rm -rf /var/lib/apt/lists/*
USER ${USERNAME}
WORKDIR /workspaces/pqc-posture
