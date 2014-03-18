#! /bin/bash

sudo bin/bin/apachectl stop;
sudo rm -rf bin

cd httpd-2.4.6;

./configure --prefix=/home/martin/Workspace/apache/bin/ --enable-suexec  --with-suexec-bin=/usr/sbin/suexec --with-suexec-caller="apache" --with-suexec-logfile=/var/log/httpd/suexec_log --with-suexec-docroot=/var/www/ --enable-mods-shared=most --enable-cgi=shared --enable-mpms-shared='prefork event';

sudo make;
sudo make install;

cd ..;
sudo cp -rf conf bin/;
