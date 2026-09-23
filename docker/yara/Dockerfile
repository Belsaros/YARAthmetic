FROM debian:bookworm-slim

ARG YARA_VERSION

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        automake \
	bison \
        ca-certificates \
	flex \
        gcc \
        git \
        libtool \
        make \
        pkg-config \
	python3 \
	python3-pip \
	python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 \
        --branch "v${YARA_VERSION}" \
        https://github.com/VirusTotal/yara.git \
        /src/yara \
    && cd /src/yara \
    && ./bootstrap.sh \
    && ./configure \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig

RUN python3 -m venv /venv \
    && /venv/bin/pip install --upgrade pip \
    && /venv/bin/pip install pytest

ENV PATH="/venv/bin:$PATH"
