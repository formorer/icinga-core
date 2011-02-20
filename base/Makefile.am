# additional include paths necessary to compile the C++ library
AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@

AM_CFLAGS = --pedantic -Wall -std=c99 -O2 -D_POSIX_C_SOURCE=200112L,-std=c99 -D_GNU_SOURCE


###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LIBRARIES = libicingacore.a 

# where to install the headers on the system
libicingacore_adir = $(includedir)/icinga

# the list of header files that belong to the library (to be installed later)
libicingacore_a_HEADERS =    

# the sources to add to the library and to add to the source distribution
libicingacore_a_SOURCES =    \
                        broker.c  commands.c  events.c    helpers.c  icingastats.c  nebmods.c   notifications.c  profiler.c    sretention.c     utils.c checks.c  config.c    flapping.c  icinga.c   logging.c      netutils.c  perfdata.c       sehandlers.c  statsprofiler.c

