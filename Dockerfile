FROM swiftdocker/swift:4.1
ENV DEBIAN_FRONTEND noninteractive
LABEL maintainer="Charles R. Portwood II <charlesportwoodii@erianna.com>"

WORKDIR /package

RUN apt update -qq && \
    apt install wget curl ca-certificates -y

RUN cd /tmp && \
    curl -qs https://download.libsodium.org/libsodium/releases/libsodium-1.0.16.tar.gz -o /tmp/libsodium-1.0.16.tar.gz && \
    tar -xf libsodium-1.0.16.tar.gz && \
    cd libsodium-1.0.16 && \
    ./configure && \
    make && \
    make install && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/libsodium.conf && \
    ldconfig