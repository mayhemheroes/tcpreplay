FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y automake pkg-config libtool autogen libpcap-dev build-essential


COPY . /repo
WORKDIR /repo
RUN autoreconf -if
RUN ./configure --disable-local-libopts --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libopts25
COPY --from=builder /install /install
