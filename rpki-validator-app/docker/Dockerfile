FROM domblack/scala
RUN yum -y install rsync

WORKDIR /opt/docker
ADD rpki-validator-app-*-dist.tar.gz .
RUN mkdir -p conf/tal/
COPY *.conf conf/
COPY docker-startup.sh ./

EXPOSE 8080

CMD /opt/docker/docker-startup.sh