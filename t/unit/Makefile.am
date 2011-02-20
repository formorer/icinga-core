bin_PROGRAMS = run_command
run_command_SOURCES = run_command.c
run_command_LDADD=-L$(top_srcdir)/base/ -licingacore -L$(top_srcdir)/common/ -licingacommon -L$(top_srcdir)/xdata/ -licingaxdata -lrt -ldl -lc -L$(top_srcdir)/cgi/ -lcgicore
AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@
#CFLAGS = --pedantic -Wall -std=c99 -O2
AM_CFLAGS = --pedantic -Wall -std=c99 -O2 -D_POSIX_C_SOURCE=200112L,-std=c99 -D_GNU_SOURCE -I$(top_srcdir)/include

