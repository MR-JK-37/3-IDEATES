FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    strace \
    procps \
    iproute2 \
    net-tools \
    file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /malware
COPY monitor.sh /malware/monitor.sh
RUN chmod +x /malware/monitor.sh

CMD ["/bin/bash"]
