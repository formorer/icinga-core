# additional include paths necessary to compile the C++ library
AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@
CFLAGS = --pedantic -Wall -std=c99 -O2
###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LIBRARIES = libcgicore.a 

# where to install the headers on the system
libcgicore_adir = $(includedir)/cgi

# the list of header files that belong to the library (to be installed later)
libcgicore_a_HEADERS =    

# the sources to add to the library and to add to the source distribution
libcgicore_a_SOURCES =   avail.c    cgiutils.c  config.c       extinfo.c  histogram.c  notifications.c  showlog.c  statusmap.c  statuswrl.c  tac.c cgiauth.c  cmd.c       extcmd_list.c  getcgi.c   history.c    outages.c        status.c   statuswml.c  summary.c    trends.c
 

