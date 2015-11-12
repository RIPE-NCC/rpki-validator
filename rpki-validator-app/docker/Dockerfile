FROM domblack/scala
RUN yum -y install rsync
EXPOSE 8080
ADD rpki-validator-app-*-dist.tar.gz /
CMD /rpki-validator-app-*/rpki-validator.sh run