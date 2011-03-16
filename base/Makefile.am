# additional include paths necessary to compile the C++ library
AM_CXXFLAGS = -std=c++0x -I$(top_srcdir)/include @AM_CXXFLAGS@ -I/
AM_CFLAGS = --pedantic -Wall -std=c++0x -D_GNU_SOURCE
#-std=c99 -O2 -D_POSIX_C_SOURCE=200112L,-std=c99
#lt_LD_CXX="g++"
###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LTLIBRARIES = libicingacore-1.0.la 

# where to install the headers on the system
libicingacore_1_0_ladir = $(includedir)/icinga

# the list of header files that belong to the library (to be installed later)
libicingacore_1_0_la_HEADERS =    

# the sources to add to the library and to add to the source distribution
libicingacore_1_0_la_SOURCES =    \
                        broker.c  commands.c  events.c    helpers.c    nebmods.c   notifications.c  profiler.c    sretention.c     utils.c checks.c  config.c    flapping.c     logging.c      netutils.c  perfdata.c       sehandlers.c  statsprofiler.c


##icinga.c main routine
#icingastats.c main routine