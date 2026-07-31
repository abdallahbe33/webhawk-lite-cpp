FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
        libdrogon-dev \
        libjsoncpp-dev \
        libpqxx-dev \
        libssl-dev \
        uuid-dev \
        zlib1g-dev \
        libsqlite3-dev \
        libbrotli-dev \
        libc-ares-dev \
        libhiredis-dev \
        libyaml-cpp-dev \
        libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source

COPY CMakeLists.txt .
COPY include ./include
COPY src ./src

RUN cmake \
        -S . \
        -B build-docker \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
    && cmake \
        --build build-docker \
        --parallel


FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libdrogon-dev \
        libpqxx-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd \
        --create-home \
        --uid 10001 \
        webhawk

WORKDIR /app

COPY --from=builder \
    /source/build-docker/webhawk_lite \
    /usr/local/bin/webhawk_lite

RUN mkdir -p /app/logs \
    && chown -R webhawk:webhawk /app

USER webhawk

EXPOSE 8080

CMD ["/usr/local/bin/webhawk_lite"]