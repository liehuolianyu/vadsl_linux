
# install config
INSTALL_PATH = /usr/local/bin
CONFIG_PATH = /etc/vadsl

# vars in this makefile
BIN_FILES = vadsl_login vadsl_logout vadsl_tnfq vadsl_listen vadsl_msg
O_FILES = vadsl_login.o vadsl_logout.o vadsl_tnfq.o vadsl_listen.o vadsl_msg.o \
	  vadsl_common.o

SH_FILES = von.sh voff.sh
CONFIG_FILES = vadsl.conf

CC = gcc
CC_FLAG = -O3 -O -Wall

# PHONY targets
.PHONY : all install clean uninstall

# default target
all : $(BIN_FILES)

# bin files

vadsl_login: vadsl_login.o vadsl_common.o
	$(CC) $(CC_FLAG) -o vadsl_login vadsl_login.o vadsl_common.o

vadsl_logout: vadsl_logout.o vadsl_common.o
	$(CC) $(CC_FLAG) -o vadsl_logout vadsl_logout.o vadsl_common.o

vadsl_tnfq: vadsl_tnfq.o vadsl_common.o
	$(CC) $(CC_FLAG) -o vadsl_tnfq vadsl_tnfq.o vadsl_common.o -std=gnu99 -pthread -lnetfilter_queue

vadsl_listen: vadsl_listen.o
	$(CC) $(CC_FLAG) -o vadsl_listen vadsl_listen.o

vadsl_msg: vadsl_msg.o
	$(CC) $(CC_FLAG) -o vadsl_msg vadsl_msg.o

# obj

vadsl_common.o:
	$(CC) $(CC_FLAG) -c vadsl_common.c

vadsl_login.o:
	$(CC) $(CC_FLAG) -c vadsl_login.c

vadsl_logout.o:
	$(CC) $(CC_FLAG) -c vadsl_logout.c

vadsl_tnfq.o:
	$(CC) $(CC_FLAG) -c vadsl_tnfq.c -std=gnu99 -pthread -lnetfilter_queue

vadsl_listen.o:
	$(CC) $(CC_FLAG) -c vadsl_listen.c

vadsl_msg.o:
	$(CC) $(CC_FLAG) -c vadsl_msg.c

# clean
clean :
	-rm $(O_FILES)
	-rm $(BIN_FILES)

# install
install : all
	@echo \>\>\>\> install: INFO: Starting install ...
	cd $(INSTALL_PATH) || mkdir $(INSTALL_PATH)
	cp $(BIN_FILES) $(SH_FILES) $(INSTALL_PATH)
	cd $(INSTALL_PATH) &&\
	    chmod 755 $(BIN_FILES) $(SH_FILES) 	&&\
	    rm von voff				;\
	    ln -s von.sh von 			&&\
	    ln -s voff.sh voff
	@echo \>\>\>\> install: INFO: Binary files has been copied to $(INSTALL_PATH)
	cd $(CONFIG_PATH) || mkdir $(CONFIG_PATH)
	@(cd $(CONFIG_PATH) && [ -f $(CONFIG_FILES) ]&& echo \>\>\>\> install: INFO: skip config file $(CONFIG_FILES) in $(CONFIG_PATH), target already exist ! ) || \
	    (cp $(CONFIG_FILES) $(CONFIG_PATH) && echo \>\>\>\> install: INFO: created config file $(CONFIG_FILES) in $(CONFIG_PATH) )
	cd $(CONFIG_PATH) &&\
	    chmod 600 $(CONFIG_FILES)
	@echo \>\>\>\> install: INFO: Install done.
	@echo \>\>\>\> install: INFO: Please edit $(CONFIG_FILES) within $(CONFIG_PATH) to your own needs

# uninstall
uninstall :
	cd $(INSTALL_PATH) &&\
	    rm $(BIN_FILES) $(SH_FILES)	;\
	    rm von voff 		;\
	    echo >/dev/null
# uninstall do not remove config file automatically
