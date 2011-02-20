# additional include paths necessary to compile the C++ library
AM_CXXFLAGS = -I$(top_srcdir)/include @AM_CXXFLAGS@
CFLAGS = --pedantic -Wall -std=c99 -O2
###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LIBRARIES = libicingaxdata.a 

# where to install the headers on the system
libicingaxdata_adir = $(includedir)/cgi

# the list of header files that belong to the library (to be installed later)
libicingaxdata_a_HEADERS =    

# the sources to add to the library and to add to the source distribution
libicingaxdata_a_SOURCES =  xcddefault.c  xdddefault.c  xodtemplate.c  xpddefault.c  xrddefault.c  xsddefault.c

 

