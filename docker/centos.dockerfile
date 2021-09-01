################################################################################
# File: centos.dockerfile
#
# Build the image:
#
#   sudo docker build -t libgcrypt -f docker/centos.dockerfile docker/
#
# Run test:
#
#   docker run -it libgcrypt bash
################################################################################

FROM centos

#
# Update the centos image and install the necessary tools.
#
RUN yum -y update && \
	yum -y install bzip2 && \
	yum -y install unzip && \
	yum -y install gcc &&  \
	yum -y install make

#
# Set the directory for the build steps
#
WORKDIR /tmp

#
# Install libgpg-error to /tmp/local
#
ADD https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.42.tar.bz2 /tmp

RUN cd /tmp && \
	bunzip2 libgpg-error-1.42.tar.bz2 && \
	tar xvf libgpg-error-1.42.tar && \
	cd /tmp/libgpg-error-1.42 && \
	./configure --prefix=/tmp/local && \
	make && \
	make install

#
# Install libgcrypt to /tmp/local
#
ADD https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.8.tar.bz2 /tmp

RUN cd /tmp && \
	bunzip2 libgcrypt-1.8.8.tar.bz2 && \
	tar xvf libgcrypt-1.8.8.tar && \
	cd /tmp/libgcrypt-1.8.8 && \
	./configure --prefix=/tmp/local --with-libgpg-error-prefix=/tmp/local && \
	make && \
	make install

#
# Build sec_handover with the prefix and compile static 
#
ADD https://github.com/dead-end/sec_handover/archive/refs/heads/master.zip /tmp

RUN cd /tmp && \
	unzip master.zip && \
	cd /tmp/sec_handover-master && \
	make LIBGCRYPT-CONFIG-PREFIX=/tmp/local STATIC=true

#
# Remove libgcrypt and run the tests.
#
RUN rm -rf /tmp/local && \
	cd /tmp/sec_handover-master && \
	make test