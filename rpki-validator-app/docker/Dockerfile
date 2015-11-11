FROM domblack/scala
RUN yum -y install rsync
ADD rpki-validator-app-2.22-SNAPSHOT-dist.tar.gz /
CMD /rpki-validator-app-2.22-SNAPSHOT/rpki-validator.sh run