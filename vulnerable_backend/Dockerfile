FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=5001

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
        libdrogon-dev \
        libjsoncpp-dev \
        libssl-dev \
        libc-ares-dev \
        uuid-dev \
        zlib1g-dev \
        libsqlite3-dev \
        libbrotli-dev \
        libpq-dev \
        libhiredis-dev \
        libyaml-cpp-dev \
        curl \
        ca-certificates \
        libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt .
COPY main.cpp .

RUN cmake \
        -S . \
        -B build \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake \
        --build build \
        --config Release \
        --parallel 2

RUN useradd \
        --create-home \
        --uid 10002 \
        vulnerable \
    && chown -R vulnerable:vulnerable /app

USER vulnerable

EXPOSE 5001

HEALTHCHECK \
    --interval=10s \
    --timeout=5s \
    --retries=10 \
    CMD curl --fail http://localhost:5001/health || exit 1

CMD ["./build/vulnerable_backend"]