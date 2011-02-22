# additional include paths necessary to compile the C++ library
AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@
AM_CFLAGS = --pedantic -Wall -std=c99 -O2 -D_POSIX_C_SOURCE=200112L,-std=c99 -D_GNU_SOURCE
###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LTLIBRARIES = libcgicore-1.0.la 

# where to install the headers on the system
libcgicore_1_0_ladir = $(includedir)/cgi

# the list of header files that belong to the library (to be installed later)
libcgicore_1_0_la_HEADERS =    

# the sources to add to the library and to add to the source distribution
libcgicore_1_0_la_SOURCES =  cgiutils.c                   cgiauth.c           getcgi.c                 

#avail.c   config.c cmd.c  extcmd_list.c extinfo.c histogram.c history.c notifications.c outages.c showlog.c status.c   statuswml.c statusmap.c summary.c    trends.c statuswrl.c tac.c
 

