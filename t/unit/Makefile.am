bin_PROGRAMS = run_command parse_config

AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@

AM_CFLAGS = --pedantic -Wall -std=c99 -O2 -D_POSIX_C_SOURCE=200112L,-std=c99 -D_GNU_SOURCE -I$(top_srcdir)/include


run_command_SOURCES = run_command.c
run_command_LDADD=$(top_srcdir)/base/libicingacore-1.0.la $(top_srcdir)/common/libicingacommon-1.0.la $(top_srcdir)/xdata/libicingaxdata-1.0.la -lrt -ldl -lc $(top_srcdir)/cgi/libcgicore-1.0.la 


parse_config_SOURCES = parse_config.c
parse_config_LDADD=$(top_srcdir)/base/libicingacore-1.0.la $(top_srcdir)/common/libicingacommon-1.0.la $(top_srcdir)/xdata/libicingaxdata-1.0.la -lrt -ldl -lc $(top_srcdir)/cgi/libcgicore-1.0.la 



