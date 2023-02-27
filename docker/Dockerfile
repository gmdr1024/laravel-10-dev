# image
FROM amazonlinux:2

# install epel, remi
RUN amazon-linux-extras install -y epel
RUN yum install -y https://rpms.remirepo.net/enterprise/remi-release-7.rpm

# install apache
RUN yum install -y httpd \
  && yum clean all

# install php
RUN yum install -y libxslt-devel libncurses-devel ncurses-compat-libs libedit-devel unzip git
RUN yum install -y --enablerepo=remi,remi-php82 --disablerepo=amzn2-core,amzn2extra-epel,epel \
php \
php-bcmath \
php-ctype \
php-fileinfo \
php-json \
php-mbstring \
php-pdo \
php-tokeniser \
php-xml
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

COPY ./entrypoint.sh /
RUN chmod 755 /entrypoint.sh
RUN usermod -u 1000 apache \
  && groupmod -g 1000 apache
ENTRYPOINT ["/entrypoint.sh"]
