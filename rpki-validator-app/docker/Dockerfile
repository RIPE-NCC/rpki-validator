FROM domblack/scala
RUN yum -y install rsync
EXPOSE 8080
ADD rpki-validator-app-2.22-SNAPSHOT-dist.tar.gz /
CMD /rpki-validator-app-2.22-SNAPSHOT/rpki-validator.sh run