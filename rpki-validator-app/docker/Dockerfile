FROM domblack/scala
RUN yum -y install rsync

WORKDIR /opt/docker
ADD rpki-validator-app-*-dist.tar.gz .
COPY *.tal conf/tal/
COPY docker-startup.sh ./

EXPOSE 8080

CMD /opt/docker/docker-startup.sh