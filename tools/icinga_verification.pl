#!/usr/bin/perl
#
# Copyright (c) 2012 Icinga Developer Team 
# Holzer Franz / Team Quality Assurance & VM 
# http://www.icinga.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
############################################################";
######   Icinga Verification and Reporting Script     ######";
######  by Frankstar / Team Quality Assurance & VM    ######";
############################################################";

use strict;
use warnings;
use DBI;
use Term::ANSIColor;
use Env qw (LANG);

################################
# Script Config
################################

#Check if we are on Windows
my $oscheck = $^O;
if( $oscheck eq 'MSWin32' ){
	print "We are on Windows, will quit now!";
	exit 1;
}
# MySQL Config if MySQL is used
my $mysqlcheck = qx(which mysql);
my ( $mysqldb, $mysqlserver, $mysqluser, $mysqlpw ) = '';

if (!$mysqlcheck ){
	print "no Mysql Server Found, skip Config";
}
else{

$mysqldb = "icinga";
print "\nMysql Found! - start Config Script\n";
print "Values in '< >' are standarts! Confirm with [Enter]\n";
print "\nEnter your MYSQL Server <localhost>: ";
$mysqlserver = <STDIN>;
chomp($mysqlserver);
if (!$mysqlserver){
	$mysqlserver = 'localhost';
}

print "Enter your MYSQL User <root>: ";
$mysqluser = <STDIN>;
chomp($mysqluser);
if (!$mysqluser){
	$mysqluser = 'root';
}

system('stty','-echo');
print "Enter your MYSQL Password: ";
$mysqlpw = <STDIN>;
chomp($mysqlpw);
system('stty','echo');
}

#Icinga Base Set
my $icinga_base = '';

print "\nEnter your Icinga base </usr/local/icinga>: ";
$icinga_base = <STDIN>;
chomp($icinga_base);

if (!$icinga_base){
	$icinga_base = '/usr/local/icinga';
}
################################
# Environment Checks 
################################

# Perl Version
my @perlversion = `perl -v`;

# Kernel version
my $osversion = `uname -rp` ;

# search for OS Information Files
my @files = `find /etc -maxdepth 1 -name *-release 2>/dev/null`;
my @distriinfo;

if (@files == 0) {
	print "no release info File found in /etc/";
	exit -1;
} else {
	@distriinfo = `cat $files[0]`;
}

# PHP Version
my @phpversion = `php -v`;

#Current Time/Date
my $date = `date`;

#Apache Info
my @apacheinfo = `httpd -V`;
chomp(@apacheinfo);

#Mysql Info
my $mysqlver = `mysql -V`;
my @mysqlver_split = split(',', $mysqlver);

######ADD JAVA HOMES, ORCALE HOMES, PATH -> via env | grep ######

################################
# Icinga Checks 
################################

# verify that idomod connected via socket to ido2db
my $idocheck = `ps aux | grep ido2db | grep -v grep | wc -l`;
chomp($idocheck);

# ido2db.cfg parsing
######## read in complete file and write needed values in an Array !##################

#ido2db socket type
my $ido2dbsocket = `cat $icinga_base/etc/ido2db.cfg | grep ^socket_type=`;
chomp($ido2dbsocket);

#ido2db TCP Port
my $ido2dbtcpport = `cat $icinga_base/etc/ido2db.cfg | grep ^tcp_port=`;
chomp($ido2dbtcpport);

#ido2db SSL Status
#use_ssl=

#ido2db Servertype
#db_servertype=

#ido2db Server Host Name
my $mysqlserver_cfg = `cat $icinga_base/etc/ido2db.cfg | grep ^db_host=`;
chomp($mysqlserver_cfg);
my @mysqlserver_cfg_split = split('=', $mysqlserver_cfg);

#ido2db Server port
#db_port=

#ido2db Server Socket
#db_socket=

#ido2db DB User
my $mysqluser_cfg = `cat $icinga_base/etc/ido2db.cfg | grep ^db_user=`;
chomp($mysqluser_cfg);
my @mysqluser_cfg_split = split('=', $mysqluser_cfg);

#ido2db DB Name
my $mysqldb_cfg = `cat $icinga_base/etc/ido2db.cfg | grep ^db_name=`;
chomp($mysqldb_cfg);
my @mysqldb_cfg_split = split('=', $mysqldb_cfg);

#ido2db Password
my $mysqlpw_cfg = `cat $icinga_base/etc/ido2db.cfg | grep ^db_pass=`;
chomp($mysqlpw_cfg);
my @mysqlpw_cfg_split = split('=', $mysqlpw_cfg);

# MySQL Checks#
my $dbh_user = '';
my $dbh_user_error = '';
my $dbh_cfg = '';
my $dbh_cfg_error = '';
my $icinga_dbversion = '';
my $sth_user = '';
my $sth1_user = '';
my @result_icingadb = ();
my @row;
my @result_icingaconninfo = ();

if (!$mysqlcheck ){
	print "no Mysql Found, skip Querys";
}
else{
# User Input Connect
$dbh_user = DBI->connect("dbi:mysql:database=$mysqldb; host=$mysqlserver:mysql_server_prepare=1", "$mysqluser", "$mysqlpw", {
	PrintError => 0,
    RaiseError => 0
}) or die color("red"), "\nMySQL Connect Failed. - check your input or MySQL Process\n", color("reset");

chomp($dbh_user_error);	
	
# Query icinga DB Version
$icinga_dbversion = 'SELECT version FROM icinga_dbversion';
$sth_user = $dbh_user->prepare($icinga_dbversion) or warn $DBI::errstr;

$sth_user->execute() or warn $DBI::errstr;


	while(@row = $sth_user->fetchrow_array()){
		push(@result_icingadb,@row);
	}

# Query icinga_conninfo
my $icinga_conninfo = 'select conninfo_id, last_checkin_time from icinga_conninfo order by connect_time desc limit 2';
$sth1_user = $dbh_user->prepare($icinga_conninfo) or warn $DBI::errstr;

$sth1_user->execute() or warn $DBI::errstr;

	while(@row = $sth1_user->fetchrow_array()){
		push(@result_icingaconninfo,"id:",@row,"\n");
	}
	
$dbh_user->disconnect();	

# ido2db.cfg Connection test
$dbh_cfg = DBI->connect("dbi:mysql:database=$mysqldb_cfg_split[1]; host=$mysqlserver_cfg_split[1]:mysql_server_prepare=1", "$mysqluser_cfg_split[1]", "$mysqlpw_cfg_split[1]", {
	PrintError => 0,
    RaiseError => 0
}) or $dbh_cfg_error = "ido2db.cfg - MySQL Connect Failed. - check your config";	

chomp($dbh_cfg_error);		
}

if (!$dbh_cfg_error){
	$dbh_cfg->disconnect();
}

# Test Print Out
# later create a fileout with the output

print "\n ############################################################";
print "\n ######   Icinga Verification and Reporting Script     ######";
print "\n ######  by Frankstar / Team Quality Assurance & VM    ######";
print "\n ############################################################";
print "\n $perlversion[1]";
print " Current Date/Time on Server: $date";
print "\n OS Information:\n";
print " OS Name: @distriinfo";
print " Kernel Version: $osversion";
print " Environment-$LANG";
print "\n Webserver Information:\n";
print " $apacheinfo[0] \n $apacheinfo[2] \n $apacheinfo[3] \n $apacheinfo[5] \n $apacheinfo[6] \n $apacheinfo[7] \n $apacheinfo[8] \n";
print "\n PHP Information:\n $phpversion[0]";
print "\n MySQL Information:\n $mysqlver_split[0]\n";
print "\n Icinga Informations:\n";
print " idomod Connections: $idocheck\n";
print " Icinga DB-Version: $result_icingadb[0]\n";
print "\n ido2db last Connection Info:\n";
print " @result_icingaconninfo";
# ido2db.cfg mysql Test Connection
print color("red"), "\n $dbh_cfg_error\n", color("reset");
#Check Services
print " Process Status:\n";

my @services = ('httpd', 'mysqld', 'snmptt', 'icinga', 'ido2db');
 
 foreach my $service (@services) {
 my $status = `/bin/ps cax | /bin/grep $service`;
	if (!$status) {
		print color("red"), " [$service]", color("reset"), " not found or started\n";
	}
	else{
		print color("green"), " [$service]", color("reset"), " found and started\n";
	}
 }
print " ############################################################\n";

exit;