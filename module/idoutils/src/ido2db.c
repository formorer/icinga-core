/***************************************************************
 * IDO2DB.C - IDO To Database Daemon
 *
 * Copyright (c) 2005-2008 Ethan Galstad
 * Copyright (c) 2009-2011 Icinga Development Team (http://www.icinga.org)
 *
 **************************************************************/

/*#define DEBUG_MEMORY 1*/

#ifdef DEBUG_MEMORY
#include <mcheck.h>
#endif

/* include our project's header files */
#include "../../../include/config.h"
#include "../include/common.h"
#include "../include/io.h"
#include "../include/utils.h"
#include "../include/protoapi.h"
#include "../include/ido2db.h"
#include "../include/queue.h"
#include "../include/db.h"
#include "../include/dbhandlers.h"
#include "../include/sla.h"


#ifdef HAVE_SSL
#include "../../../include/dh.h"
#endif

extern int use_ssl;

extern int errno;

extern char *ido2db_db_tablenames[IDO2DB_MAX_DBTABLES];

/* sla config variable */
int enable_sla = 0;

#ifdef USE_LIBDBI
extern int ido2db_check_dbd_driver(void);
#endif

ido_dbuf dbuf;

/* threading for buffer */
pthread_t queue_thread;
pthread_t dbqueue_thread[IDO2DB_DBQUEUE_THREADS];

/* sink buffer */
char *ido2db_buffer_file = NULL;
unsigned long ido2db_sink_buffer_slots = IDO2DB_SINK_BUFFER_SLOTS;
ido2db_sink_buffer sinkbuf;

/* dbqueue buffer */
ido2db_dbqueue_buf dbqueue_buf;
unsigned long ido2db_dbqueue_buf_slots = IDO2DB_DBQUEUE_BUF_SLOTS;

/* lock for the logs */
pthread_mutex_t log_lock;

/*
 * libdbi dbi_conn_query, dbi_conn_ping, dbi_conn_error
 * are NOT threadsafe and therefore need to be
 * protected by a mutex
 *
 * see https://dev.icinga.org/issues/2034
 */
pthread_mutex_t dbi_conn_query_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dbi_conn_ping_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dbi_conn_error_lock = PTHREAD_MUTEX_INITIALIZER;


static void *ido2db_thread_cleanup_exit_handler(void *);
static void *ido2db_thread_worker_exit_handler(void *);
static void *ido2db_thread_dbqueue_exit_handler(void *);


#ifdef HAVE_SSL
SSL_METHOD *meth;
SSL_CTX *ctx;
int allow_weak_random_seed = IDO_FALSE;
#endif

char *ido2db_config_file = NULL;
char *lock_file = NULL;
char *ido2db_user = NULL;
char *ido2db_group = NULL;

int ido2db_sd = 0;
int ido2db_socket_type = IDO_SINK_UNIXSOCKET;
char *ido2db_socket_name = NULL;

int ido2db_tcp_port = IDO_DEFAULT_TCP_PORT;
int ido2db_use_inetd = IDO_FALSE;

int ido2db_show_version = IDO_FALSE;
int ido2db_show_license = IDO_FALSE;
int ido2db_show_help = IDO_FALSE;

int ido2db_run_foreground = IDO_FALSE;

ido2db_dbconfig ido2db_db_settings;
ido2db_idi thread_idi;
ido2db_idi dbqueue_idi[IDO2DB_DBQUEUE_THREADS];
pthread_t thread_pool[IDO2DB_NR_OF_THREADS];

time_t ido2db_db_last_checkin_time = 0L;

char *ido2db_debug_file = NULL;
int ido2db_debug_level = IDO2DB_DEBUGL_NONE;
int ido2db_debug_verbosity = IDO2DB_DEBUGV_BASIC;
FILE *ido2db_debug_file_fp = NULL;
unsigned long ido2db_max_debug_file_size = 0L;

int stop_signal_detected = IDO_FALSE;

char *sigs[35] = {"EXIT", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "UNUSED", "ZERR", "DEBUG", (char *)NULL};


int ido2db_open_debug_log(void);
int ido2db_close_debug_log(void);


int dummy;	/* reduce compiler warnings */


int main(int argc, char **argv) {
	int result = IDO_OK;

#ifdef DEBUG_MEMORY
	mtrace();
#endif
#ifdef HAVE_SSL
	DH *dh;
	char seedfile[FILENAME_MAX];
	int i, c;
#endif
#ifdef USE_LIBDBI
	dbi_driver driver;
	int numdrivers;

	driver = NULL;
#endif
	result = ido2db_process_arguments(argc, argv);

	if (result != IDO_OK || ido2db_show_help == IDO_TRUE || ido2db_show_license == IDO_TRUE || ido2db_show_version == IDO_TRUE) {

		if (result != IDO_OK)
			printf("Incorrect command line arguments supplied\n");

		printf("\n");
		printf("%s %s\n", IDO2DB_NAME, IDO2DB_VERSION);
		printf("Copyright(c) 2005-2008 Ethan Galstad (nagios@nagios.org)\n");
		printf("Copyright(c) 2009-2011 Icinga Development Team (http://www.icinga.org)\n");
		printf("Last Modified: %s\n", IDO2DB_DATE);
		printf("License: GPL v2\n");
#ifdef HAVE_SSL
		printf("SSL/TLS Available: Anonymous DH Mode, OpenSSL 0.9.6 or higher required\n");
#endif
		printf("\n");
		printf("Stores Icinga event and configuration data to a database for later retrieval\n");
		printf("and processing.  Clients that are capable of sending data to the IDO2DB daemon\n");
		printf("include the LOG2IDO utility and IDO2DB event broker module.\n");
		printf("\n");
		printf("Usage: %s -c <config_file> [-i] [-f]\n", argv[0]);
		printf("\n");
		printf("-i  = Run under INETD/XINETD.\n");
		printf("-f  = Don't daemonize, run in foreground.\n");
		printf("\n");
		exit(1);
	}

	/* initialize variables */
	ido2db_initialize_variables();

	/* process config file */
	if (ido2db_process_config_file(ido2db_config_file) != IDO_OK) {
		printf("Error processing config file '%s'.\n", ido2db_config_file);
		exit(1);
	}

	/* print starting info to syslog */
	syslog(LOG_USER | LOG_INFO, "%s %s (%s) Copyright (c) 2005-2008 Ethan Galstad (nagios@nagios.org), Copyright (c) 2009-2011 Icinga Development Team (http://www.icinga.org))", IDO2DB_NAME, IDO2DB_VERSION, IDO2DB_DATE);
	syslog(LOG_USER | LOG_INFO, "%s %s starting... (PID=%d)\n", IDO2DB_NAME, IDO2DB_VERSION, (int)getpid());

	if (ido2db_socket_type == IDO_SINK_UNIXSOCKET && use_ssl == IDO_TRUE) {
		printf("SSL is not allowed on socket_type=unix\n");
		exit(1);
	}

#ifdef HAVE_SSL
	/* initialize SSL */
	if (use_ssl == IDO_TRUE) {
		SSL_library_init();
		SSLeay_add_ssl_algorithms();
		meth = SSLv23_server_method();
		SSL_load_error_strings();

		/* use week random seed if necessary */
		if (allow_weak_random_seed && (RAND_status() == 0)) {

			if (RAND_file_name(seedfile, sizeof(seedfile) - 1))
				if (RAND_load_file(seedfile, -1))
					RAND_write_file(seedfile);

			if (RAND_status() == 0) {
				syslog(LOG_ERR, "Warning: SSL/TLS uses a weak random seed which is highly discouraged");
				srand(time(NULL));
				for (i = 0; i < 500 && RAND_status() == 0; i++) {
					for (c = 0; c < sizeof(seedfile); c += sizeof(int)) {
						*((int *)(seedfile + c)) = rand();
					}
					RAND_seed(seedfile, sizeof(seedfile));
				}
			}
		}
		if ((ctx = SSL_CTX_new(meth)) == NULL) {
			syslog(LOG_ERR, "Error: could not create SSL context.\n");
			exit(1);
		}

		/* ADDED 01/19/2004 */
		/* use only TLSv1 protocol */
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

		/* use anonymous DH ciphers */
		SSL_CTX_set_cipher_list(ctx, "ADH");
		dh = get_dh512();
		SSL_CTX_set_tmp_dh(ctx, dh);
		DH_free(dh);
		syslog(LOG_INFO, "INFO: SSL/TLS initialized. All network traffic will be encrypted.");
	} else {
		syslog(LOG_INFO, "INFO: SSL/TLS NOT initialized. Network encryption DISABLED.");
	}
	/*Fin Hack SSL*/
#endif

	/* make sure we're good to go */
	if (ido2db_check_init_reqs() != IDO_OK) {
		printf("One or more required parameters is missing or incorrect.\n");
		exit(1);
	}

	/* make sure we support the db option chosen... */

	/******************************/
#ifdef USE_LIBDBI /* everything else will be libdbi */
	if (ido2db_check_dbd_driver() == IDO_FALSE) {
		printf("Support for the specified database server is either not yet supported, or was not found on your system.\n");

		numdrivers = dbi_initialize(NULL);
		if (numdrivers == -1)
			numdrivers = 0;

		fprintf(stderr, "%d drivers available: ", numdrivers);
		while ((driver = dbi_driver_list(driver)) != NULL) {

			fprintf(stderr, "%s ", dbi_driver_get_name(driver));
		}
		fprintf(stderr, "\n");

#ifdef HAVE_SSL
		if (use_ssl == IDO_TRUE)
			SSL_CTX_free(ctx);
#endif

		exit(1);
	}

	/* 2009-10-16 Michael Friedrich: libdbi Oracle driver is not yet working, remains broken */
	if (ido2db_db_settings.server_type == IDO2DB_DBSERVER_ORACLE) {
		printf("Support for libdbi Oracle driver is not yet working.\n");
		exit(1);
	}
#endif

	/******************************/
#ifdef USE_PGSQL /* pgsql */

	/* we don't have a driver check here */
#endif

	/******************************/
#ifdef USE_ORACLE /* Oracle ocilib specific */

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db with ocilib() driver check\n");
	if (OCI_GetOCIRuntimeVersion == OCI_UNKNOWN) {
		printf("Unknown ocilib runtime version detected. Exiting...\n");

#ifdef HAVE_SSL
		if (use_ssl == IDO_TRUE)
			SSL_CTX_free(ctx);
#endif

		exit(1);
	}

#endif /* Oracle ocilib specific */
	/******************************/

	/* initialize signal handling */
	signal(SIGQUIT, ido2db_parent_sighandler);
	signal(SIGTERM, ido2db_parent_sighandler);
	signal(SIGINT, ido2db_parent_sighandler);
	signal(SIGSEGV, ido2db_parent_sighandler);
	signal(SIGFPE, ido2db_parent_sighandler);
	signal(SIGCHLD, ido2db_parent_sighandler);

	/* drop privileges */
	ido2db_drop_privileges(ido2db_user, ido2db_group);

	/* open debug log */
	ido2db_open_debug_log();

	/* if we're running under inetd... */
	if (ido2db_use_inetd == IDO_TRUE) {

		/* redirect STDERR to /dev/null */
		close(2);
		open("/dev/null", O_WRONLY);

		/* handle the connection */
		ido2db_handle_client_connection(0);
	}

	/* standalone daemon... */
	else {

		/* create socket and wait for clients to connect */
		if (ido2db_wait_for_connections() == IDO_ERROR)
			return 1;
	}

	/* tell the log we're done */
	syslog(LOG_USER | LOG_INFO, "Successfully shutdown... (PID=%d)\n", (int)getpid());

	/* close debug log */
	ido2db_close_debug_log();

	/* free memory */
	ido2db_free_program_memory();

#ifdef HAVE_SSL
	if (use_ssl == IDO_TRUE)
		SSL_CTX_free(ctx);
#endif

	return 0;
}


/* process command line arguments */
int ido2db_process_arguments(int argc, char **argv) {
	char optchars[32];
	int c = 1;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		{"configfile", required_argument, 0, 'c'},
		{"inetd", no_argument, 0, 'i'},
		{"foreground", no_argument, 0, 'f'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
		{"version", no_argument, 0, 'V'},
		{0, 0, 0, 0}
	};
#endif

	/* no options were supplied */
	if (argc < 2) {
		ido2db_show_help = IDO_TRUE;
		return IDO_OK;
	}

	snprintf(optchars, sizeof(optchars), "c:ifhlV");

	while (1) {
#ifdef HAVE_GETOPT_H
		c = getopt_long(argc, argv, optchars, long_options, &option_index);
#else
		c = getopt(argc, argv, optchars);
#endif
		if (c == -1 || c == EOF)
			break;

		/* process all arguments */
		switch (c) {

		case '?':
		case 'h':
			ido2db_show_help = IDO_TRUE;
			break;
		case 'V':
			ido2db_show_version = IDO_TRUE;
			break;
		case 'l':
			ido2db_show_license = IDO_TRUE;
			break;
		case 'c':
			ido2db_config_file = strdup(optarg);
			break;
		case 'i':
			ido2db_use_inetd = IDO_TRUE;
			break;
		case 'f':
			ido2db_run_foreground = IDO_TRUE;
			break;
		default:
			return IDO_ERROR;
			break;
		}
	}

	/* make sure required args were supplied */
	if ((ido2db_config_file == NULL) && ido2db_show_help == IDO_FALSE && ido2db_show_version == IDO_FALSE  && ido2db_show_license == IDO_FALSE)
		return IDO_ERROR;

	return IDO_OK;
}



/****************************************************************************/
/* CONFIG FUNCTIONS                                                         */
/****************************************************************************/

/* process all config vars in a file */
int ido2db_process_config_file(char *filename) {
	ido_mmapfile *thefile = NULL;
	char *buf = NULL;
	int result = IDO_OK;

	/* open the file */
	if ((thefile = ido_mmap_fopen(filename)) == NULL) {
		syslog(LOG_ERR, "Error: Unable to open configuration file %s: %s\n", filename, strerror(errno));
		return IDO_ERROR;
	}

	/* process each line of the file */
	while ((buf = ido_mmap_fgets(thefile))) {

		/* skip comments */
		if (buf[0] == '#') {
			free(buf);
			continue;
		}

		/* skip blank lines */
		if (!strcmp(buf, "")) {
			free(buf);
			continue;
		}

		/* process the variable */
		result = ido2db_process_config_var(buf);

		/* free memory */
		free(buf);

		if (result != IDO_OK)
			break;
	}

	/* close the file */
	ido_mmap_fclose(thefile);

	return result;
}


/* process a single module config variable */
int ido2db_process_config_var(char *arg) {
	char *var = NULL;
	char *val = NULL;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_process_config_var() start\n");

	/* split var/val */
	var = strtok(arg, "=");
	val = strtok(NULL, "\n");

	/* skip incomplete var/val pairs */
	if (var == NULL || val == NULL)
		return IDO_OK;

	/* process the variable... */

	if (!strcmp(var, "lock_file")) {
		if ((lock_file = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "socket_type")) {
		if (!strcmp(val, "tcp"))
			ido2db_socket_type = IDO_SINK_TCPSOCKET;
		else
			ido2db_socket_type = IDO_SINK_UNIXSOCKET;
	} else if (!strcmp(var, "socket_name")) {
		if ((ido2db_socket_name = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "tcp_port")) {
		ido2db_tcp_port = atoi(val);
	} else if (!strcmp(var, "db_servertype")) {
		if (!strcmp(val, "mysql")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_MYSQL;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "pgsql")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_PGSQL;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "db2")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_DB2;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "firebird")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_FIREBIRD;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "freetds")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_FREETDS;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "ingres")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_INGRES;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "msql")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_MSQL;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "oracle")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_ORACLE;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "sqlite")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_SQLITE;
			ido2db_db_settings.dbserver = strdup(val);
		} else if (!strcmp(val, "sqlite3")) {
			ido2db_db_settings.server_type = IDO2DB_DBSERVER_SQLITE3;
			ido2db_db_settings.dbserver = strdup(val);
		} else
			return IDO_ERROR;
	} else if (!strcmp(var, "db_host")) {
		if ((ido2db_db_settings.host = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "db_port")) {
		ido2db_db_settings.port = atoi(val);
	} else if (!strcmp(var, "db_user")) {
		if ((ido2db_db_settings.username = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "db_pass")) {
		if ((ido2db_db_settings.password = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "db_name")) {
		if ((ido2db_db_settings.dbname = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "db_prefix")) {
		if ((ido2db_db_settings.dbprefix = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "db_socket")) {
		if ((ido2db_db_settings.dbsocket = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "max_timedevents_age"))
		ido2db_db_settings.max_timedevents_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_systemcommands_age"))
		ido2db_db_settings.max_systemcommands_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_servicechecks_age"))
		ido2db_db_settings.max_servicechecks_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_hostchecks_age"))
		ido2db_db_settings.max_hostchecks_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_eventhandlers_age"))
		ido2db_db_settings.max_eventhandlers_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_externalcommands_age"))
		ido2db_db_settings.max_externalcommands_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_logentries_age"))
		ido2db_db_settings.max_logentries_age = strtoul(val, NULL, 0) * 60;
	else if (!strcmp(var, "max_acknowledgements_age"))
		ido2db_db_settings.max_acknowledgements_age = strtoul(val, NULL, 0) * 60;

	else if (!strcmp(var, "trim_db_interval"))
		ido2db_db_settings.trim_db_interval = strtoul(val, NULL, 0);

	else if (!strcmp(var, "housekeeping_thread_startup_delay"))
		ido2db_db_settings.housekeeping_thread_startup_delay = strtoul(val, NULL, 0);

	else if ((!strcmp(var, "ido2db_user")) || (!strcmp(var, "ido2db_user")))
		ido2db_user = strdup(val);
	else if ((!strcmp(var, "ido2db_group")) || (!strcmp(var, "ido2db_group")))
		ido2db_group = strdup(val);

	else if (!strcmp(var, "debug_file")) {
		if ((ido2db_debug_file = strdup(val)) == NULL)
			return IDO_ERROR;
	} else if (!strcmp(var, "debug_level"))
		ido2db_debug_level = atoi(val);
	else if (!strcmp(var, "debug_verbosity"))
		ido2db_debug_verbosity = atoi(val);
	else if (!strcmp(var, "max_debug_file_size"))
		ido2db_max_debug_file_size = strtoul(val, NULL, 0);
	else if (!strcmp(var, "use_ssl")) {
		if (strlen(val) == 1) {
			if (isdigit((int)val[strlen(val)-1]) != IDO_FALSE)
				use_ssl = atoi(val);
			else
				use_ssl = 0;
		}
	} else if (!strcmp(var, "clean_realtime_tables_on_core_startup")) {
		if (strlen(val) != 1 || val[0] < '0' || val[0] > '1') {
			return IDO_ERROR;
		}
		ido2db_db_settings.clean_realtime_tables_on_core_startup = (atoi(val) > 0) ? IDO_TRUE : IDO_FALSE;
	} else if (!strcmp(var, "clean_config_tables_on_core_startup")) {
		if (strlen(val) != 1 || val[0] < '0' || val[0] > '1') {
			return IDO_ERROR;
		}
		ido2db_db_settings.clean_config_tables_on_core_startup = (atoi(val) > 0) ? IDO_TRUE : IDO_FALSE;
	}

	else if (!strcmp(var, "oci_errors_to_syslog")) {
		ido2db_db_settings.oci_errors_to_syslog = (atoi(val) > 0) ? IDO_TRUE : IDO_FALSE;
	} else if (!strcmp(var, "oracle_trace_level")) {
		ido2db_db_settings.oracle_trace_level = atoi(val);
	} else if (strcmp(var, "enable_sla") == 0) {
		enable_sla = strtoul(val, NULL, 0);
	}
        else if (!strcmp(var, "output_buffer_items")) {
                ido2db_sink_buffer_slots = strtoul(val, NULL, 0);

                /* do not allow smaller buffers */
                if(ido2db_sink_buffer_slots < IDO2DB_SINK_BUFFER_SLOTS)
                        ido2db_sink_buffer_slots = IDO2DB_SINK_BUFFER_SLOTS;
        }
        else if (!strcmp(var, "buffer_file")) {
                ido2db_buffer_file = strdup(val);
		if(ido2db_buffer_file == NULL) {
			ido2db_buffer_file = strdup("/tmp/ido2db.tmp");
		}
	}

	//syslog(LOG_ERR,"ido2db_process_config_var(%s) end\n",var);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_process_config_var(%s) end\n", var);

	return IDO_OK;
}


/* initialize variables */
int ido2db_initialize_variables(void) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_initialize_variables() start\n");

	ido2db_db_settings.server_type = IDO2DB_DBSERVER_NONE;
	ido2db_db_settings.host = NULL;
	ido2db_db_settings.port = 0;
	ido2db_db_settings.username = NULL;
	ido2db_db_settings.password = NULL;
	ido2db_db_settings.dbname = NULL;
	ido2db_db_settings.dbprefix = NULL;
	ido2db_db_settings.dbsocket = NULL;
	ido2db_db_settings.max_timedevents_age = 0L;
	ido2db_db_settings.max_systemcommands_age = 0L;
	ido2db_db_settings.max_servicechecks_age = 0L;
	ido2db_db_settings.max_hostchecks_age = 0L;
	ido2db_db_settings.max_eventhandlers_age = 0L;
	ido2db_db_settings.max_externalcommands_age = 0L;
	ido2db_db_settings.max_logentries_age = 0L;
	ido2db_db_settings.max_acknowledgements_age = 0L;
	ido2db_db_settings.trim_db_interval = (unsigned long)DEFAULT_TRIM_DB_INTERVAL; /* set the default if missing in ido2db.cfg */
	ido2db_db_settings.housekeeping_thread_startup_delay = (unsigned long)DEFAULT_HOUSEKEEPING_THREAD_STARTUP_DELAY; /* set the default if missing in ido2db.cfg */
	ido2db_db_settings.clean_realtime_tables_on_core_startup = IDO_TRUE; /* default is cleaning on startup */
	ido2db_db_settings.clean_config_tables_on_core_startup = IDO_TRUE;
	ido2db_db_settings.oci_errors_to_syslog = DEFAULT_OCI_ERRORS_TO_SYSLOG;
	ido2db_db_settings.oracle_trace_level = ORACLE_TRACE_LEVEL_OFF;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_initialize_variables() end\n");
	return IDO_OK;
}



/****************************************************************************/
/* CLEANUP FUNCTIONS                                                       */
/****************************************************************************/

/* free program memory */
int ido2db_free_program_memory(void) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_program_memory() start\n");

	if (ido2db_config_file) {
		free(ido2db_config_file);
		ido2db_config_file = NULL;
	}
	if (ido2db_user) {
		free(ido2db_user);
		ido2db_user = NULL;
	}
	if (ido2db_group) {
		free(ido2db_group);
		ido2db_group = NULL;
	}
	if (ido2db_socket_name) {
		free(ido2db_socket_name);
		ido2db_socket_name = NULL;
	}
	if (ido2db_db_settings.host) {
		free(ido2db_db_settings.host);
		ido2db_db_settings.host = NULL;
	}
	if (ido2db_db_settings.username) {
		free(ido2db_db_settings.username);
		ido2db_db_settings.username = NULL;
	}
	if (ido2db_db_settings.password) {
		free(ido2db_db_settings.password);
		ido2db_db_settings.password = NULL;
	}
	if (ido2db_db_settings.dbname) {
		free(ido2db_db_settings.dbname);
		ido2db_db_settings.dbname = NULL;
	}
	if (ido2db_db_settings.dbprefix) {
		free(ido2db_db_settings.dbprefix);
		ido2db_db_settings.dbprefix = NULL;
	}
	if (ido2db_db_settings.dbsocket) {
		free(ido2db_db_settings.dbsocket);
		ido2db_db_settings.dbsocket = NULL;
	}
	if (ido2db_debug_file) {
		free(ido2db_debug_file);
		ido2db_debug_file = NULL;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_program_memory() end\n");
	return IDO_OK;
}



/****************************************************************************/
/* UTILITY FUNCTIONS                                                        */
/****************************************************************************/

int ido2db_check_init_reqs(void) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_init_reqs() start\n");

	if (ido2db_socket_type == IDO_SINK_UNIXSOCKET) {
		if (ido2db_socket_name == NULL) {
			printf("No socket name specified.\n");
			return IDO_ERROR;
		}
	}
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_init_reqs() end\n");
	return IDO_OK;
}



/* drops privileges */
int ido2db_drop_privileges(char *user, char *group) {
	uid_t uid = -1;
	gid_t gid = -1;
	struct group *grp;
	struct passwd *pw;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_drop_privileges() start\n");

	/* set effective group ID */
	if (group != NULL) {

		/* see if this is a group name */
		if (strspn(group, "0123456789") < strlen(group)) {
			grp = (struct group *)getgrnam(group);
			if (grp != NULL)
				gid = (gid_t)(grp->gr_gid);
			else
				syslog(LOG_ERR, "Warning: Could not get group entry for '%s'", group);
			endgrent();
		}

		/* else we were passed the GID */
		else
			gid = (gid_t)atoi(group);

		/* set effective group ID if other than current EGID */
		if (gid != getegid()) {

			if (setgid(gid) == -1)
				syslog(LOG_ERR, "Warning: Could not set effective GID=%d", (int)gid);
		}
	}


	/* set effective user ID */
	if (user != NULL) {

		/* see if this is a user name */
		if (strspn(user, "0123456789") < strlen(user)) {
			pw = (struct passwd *)getpwnam(user);
			if (pw != NULL)
				uid = (uid_t)(pw->pw_uid);
			else
				syslog(LOG_ERR, "Warning: Could not get passwd entry for '%s'", user);
			endpwent();
		}

		/* else we were passed the UID */
		else
			uid = (uid_t)atoi(user);

		/* set effective user ID if other than current EUID */
		if (uid != geteuid()) {

#ifdef HAVE_INITGROUPS
			/* initialize supplementary groups */
			if (initgroups(user, gid) == -1) {
				if (errno == EPERM)
					syslog(LOG_ERR, "Warning: Unable to change supplementary groups using initgroups()");
				else {
					syslog(LOG_ERR, "Warning: Possibly root user failed dropping privileges with initgroups()");
					return IDO_ERROR;
				}
			}
#endif

			if (setuid(uid) == -1)
				syslog(LOG_ERR, "Warning: Could not set effective UID=%d", (int)uid);
		}
	}
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_drop_privileges() end\n");
	return IDO_OK;
}


int ido2db_daemonize(void) {
	pid_t pid = -1;
	/* int pidno=0; */
	int lockfile = 0;
	struct flock lock;
	int val = 0;
	char buf[256];
	char *msg = NULL;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() start\n");

	umask(S_IWGRP | S_IWOTH);

	/* get a lock on the lockfile */
	if (lock_file) {
		lockfile = open(lock_file, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if (lockfile < 0) {
			if (asprintf(&msg, "Failed to obtain lock on file %s: %s\n", lock_file, strerror(errno)) == -1)
				msg = NULL;
			perror(msg);
			ido2db_cleanup_socket();
			return IDO_ERROR;
		}

		/* see if we can read the contents of the lockfile */
		if ((val = read(lockfile, buf, (size_t)10)) < 0) {
			if (asprintf(&msg, "Lockfile exists but cannot be read") == -1)
				msg = NULL;
			perror(msg);
			ido2db_cleanup_socket();
			return IDO_ERROR;
		}

		/* place a file lock on the lock file */
		lock.l_type = F_WRLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;
		if (fcntl(lockfile, F_SETLK, &lock) < 0) {
			if (errno == EACCES || errno == EAGAIN) {
				fcntl(lockfile, F_GETLK, &lock);
				if (asprintf(&msg, "Lockfile '%s' looks like its already held by another instance (%d).  Bailing out...", lock_file, (int)lock.l_pid) == -1)
					msg = NULL;
			} else  {
				if (asprintf(&msg, "Cannot lock lockfile '%s': %s. Bailing out...", lock_file, strerror(errno)) == -1)
					msg = NULL;
			}
			perror(msg);
			ido2db_cleanup_socket();
			return IDO_ERROR;
		}
	}

	/* fork */
	if ((pid = fork()) < 0) {
		perror("Fork error");
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() parent fork error\n");
		ido2db_cleanup_socket();
		return IDO_ERROR;
	}

	/* parent process goes away... */
	else if ((int)pid != 0) {
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() parent process goes away\n");
		ido2db_free_program_memory();
		exit(0);
	}

	/* child forks again... */
	else {
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() child forks again\n");

		if ((pid = fork()) < 0) {
			perror("Fork error");
			ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() child fork error\n");
			ido2db_cleanup_socket();
			return IDO_ERROR;
		}

		/* first child process goes away.. */
		else if ((int)pid != 0) {
			ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() first child process goes away\n");
			ido2db_free_program_memory();
			exit(0);
		}

		/* grandchild continues... */
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() grandchild continues and  becomes session leader\n");
		/* grandchild becomes session leader... */
		setsid();
	}

	if (lock_file) {
		/* write PID to lockfile... */
		lseek(lockfile, 0, SEEK_SET);
		dummy = ftruncate(lockfile, 0);
		sprintf(buf, "%d\n", (int)getpid());
		dummy = write(lockfile, buf, strlen(buf));

		/* make sure lock file stays open while program is executing... */
		val = fcntl(lockfile, F_GETFD, 0);
		val |= FD_CLOEXEC;
		fcntl(lockfile, F_SETFD, val);
	}

	/* close existing stdin, stdout, stderr */
	close(0);
	if (ido2db_run_foreground == IDO_FALSE)
		close(1);
	close(2);

	/* re-open stdin, stdout, stderr with known values */
	open("/dev/null", O_RDONLY);
	if (ido2db_run_foreground == IDO_FALSE)
		open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_daemonize() end\n");

	return IDO_OK;
}


int ido2db_cleanup_socket(void) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_cleanup_socket() start\n");

	/* we're running under INETD */
	if (ido2db_use_inetd == IDO_TRUE)
		return IDO_OK;

	/* close the socket */
	shutdown(ido2db_sd, 2);
	close(ido2db_sd);

	/* unlink the file */
	if (ido2db_socket_type == IDO_SINK_UNIXSOCKET)
		unlink(ido2db_socket_name);

	if (lock_file)
		unlink(lock_file);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_cleanup_socket() end\n");
	return IDO_OK;
}


void ido2db_parent_sighandler(int sig) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_parent_sighandler() start\n");
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "processing signal '%d'\n", sig);

	/* not possible as parent */
	/* syslog(LOG_USER | LOG_INFO, "Processing SIG%s...\n", sigs[sig]); */

	switch (sig) {
	case SIGTERM:
	case SIGINT:
		/* forward signal to all members of this group of processes */
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "forward signal to all members of this group of processes\n");
		kill(0, sig);
		break;
	case SIGCHLD:
		/* cleanup children that exit, so we don't have zombies */
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "cleanup children that exit, so we don't have zombies\n");
		while (waitpid(-1, NULL, WNOHANG) > 0);
		return;

	default:
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 0, "Caught the Signal '%d' but don't care about this.\n", sig);
	}

	/* cleanup the socket */
	ido2db_cleanup_socket();

	/* free memory */
	ido2db_free_program_memory();

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_parent_sighandler() end\n");

	exit(0);

	return;
}


void ido2db_child_sighandler(int sig) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_child_sighandler() start\n");
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "Child caught signal '%d' exiting\n", sig);
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_child_sighandler() end\n");

	/* don't run into a race condition */
	//syslog(LOG_USER | LOG_INFO, "Caught SIG%s, cleaning up and exiting...\n", sigs[sig]);

	if (ido2db_run_foreground == IDO_TRUE) {
		/* cleanup the socket */
		ido2db_cleanup_socket();

		/* free memory */
		ido2db_free_program_memory();
	}

	/* terminate threads */
	ido2db_terminate_threads();

	_exit(0);

	return;
}


/****************************************************************************/
/* UTILITY FUNCTIONS                                                        */
/****************************************************************************/


int ido2db_wait_for_connections(void) {
	int sd_flag = 1;
	int new_sd = 0;
	pid_t new_pid = -1;
	struct sockaddr_un server_address_u;
	struct sockaddr_in server_address_i;
	struct sockaddr_un client_address_u;
	struct sockaddr_in client_address_i;
	socklen_t client_address_length;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_wait_for_connections() start\n");

	/* TCP socket */
	if (ido2db_socket_type == IDO_SINK_TCPSOCKET) {

		/* create a socket */
		if (!(ido2db_sd = socket(PF_INET, SOCK_STREAM, 0))) {
			perror("Cannot create socket");
			return IDO_ERROR;
		}

		/* set the reuse address flag so we don't get errors when restarting */
		sd_flag = 1;
		if (setsockopt(ido2db_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&sd_flag, sizeof(sd_flag)) < 0) {
			printf("Could not set reuse address option on socket!\n");
			return IDO_ERROR;
		}

		/* clear the address */
		bzero((char *)&server_address_i, sizeof(server_address_i));
		server_address_i.sin_family = AF_INET;
		server_address_i.sin_addr.s_addr = INADDR_ANY;
		server_address_i.sin_port = htons(ido2db_tcp_port);

		/* bind the socket */
		if ((bind(ido2db_sd, (struct sockaddr *)&server_address_i, sizeof(server_address_i)))) {
			close(ido2db_sd);
			perror("Could not bind socket");
			return IDO_ERROR;
		}

		client_address_length = (socklen_t)sizeof(client_address_i);
	}

	/* UNIX domain socket */
	else {

		/* create a socket */
		if (!(ido2db_sd = socket(AF_UNIX, SOCK_STREAM, 0))) {
			perror("Cannot create socket");
			return IDO_ERROR;
		}

		/* copy the socket path */
		strncpy(server_address_u.sun_path, ido2db_socket_name, sizeof(server_address_u.sun_path));
		server_address_u.sun_family = AF_UNIX;

		/* bind the socket */
		if ((bind(ido2db_sd, (struct sockaddr *)&server_address_u, SUN_LEN(&server_address_u)))) {
			close(ido2db_sd);
			perror("Could not bind socket");
			return IDO_ERROR;
		}

		client_address_length = (socklen_t)sizeof(client_address_u);
	}

	/* listen for connections */
	if ((listen(ido2db_sd, 1))) {
		perror("Cannot listen on socket");
		ido2db_cleanup_socket();
		return IDO_ERROR;
	}


	/* daemonize */
	if (ido2db_run_foreground == IDO_FALSE) {
		if (ido2db_daemonize() != IDO_OK) {
			ido2db_cleanup_socket();
			return IDO_ERROR;
		}
		syslog(LOG_USER | LOG_INFO, "Finished daemonizing... (New PID=%d)\n", (int)getpid());
	}

	/* accept connections... */
	while (1) {

		while (1) {

			new_sd = accept(ido2db_sd, (ido2db_socket_type == IDO_SINK_TCPSOCKET) ? (struct sockaddr *)&client_address_i : (struct sockaddr *)&client_address_u, (socklen_t *)&client_address_length);


			/* ToDo:  Hendrik 08/12/2009
			 * If both ends think differently about SSL encryption, data from a ido2db will
			 * be lost forever (likewise on database errors/misconfiguration)
			 * This seems a good place to output some information from which client
			 * a possible misconfiguration comes from.
			 * Logging the ip address together with the ido2db instance name might be
			 * a great hint for further error hunting
			 */

			if (new_sd >= 0)
				/* data available */
				syslog(LOG_USER | LOG_INFO, "Client connected, data available.\n");
			break;
			if (errno == EINTR) {
				/* continue */
			} else {
				perror("Accept error");
				ido2db_cleanup_socket();
				return IDO_ERROR;
			}
		}

		if (ido2db_run_foreground == IDO_FALSE) {
			/* fork... */
			new_pid = fork();

			switch (new_pid) {
			case -1:
				/* parent simply prints an error message and keeps on going... */
				perror("Fork error");
				close(new_sd);
				break;

			case 0:
				/* child processes data... */
				ido2db_handle_client_connection(new_sd);

				/* close socket when we're done */
				close(new_sd);
				return IDO_OK;
				break;

			default:
				/* parent keeps on going... */
				close(new_sd);
				break;
			}
		} else {
			/* child processes data... */
			ido2db_handle_client_connection(new_sd);

			/* close socket when we're done */
			close(new_sd);
		}

#ifdef DEBUG_IDO2DB_EXIT_AFTER_CONNECTION
		break;
#endif
	}

	/* cleanup after ourselves */
	ido2db_cleanup_socket();

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_wait_for_connections() end\n");

	return IDO_OK;
}


int ido2db_handle_client_connection(int sd) {
	int dbuf_chunk = 2048;
	ido2db_idi idi;
	char buf[512];
	int result = 0;
	int error = IDO_FALSE;
	ido2db_thread_data *thread_data = (ido2db_thread_data *)calloc(1, sizeof(ido2db_thread_data));

        struct timespec delay;
	int t;
	int pthread_ret = 0;
	//sigset_t newmask;
	pthread_attr_t attr_dbqueue;

#ifdef HAVE_SSL
	SSL *ssl = NULL;
#endif

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() start\n");

	/* open syslog facility */
	/*openlog("ido2db",0,LOG_DAEMON);*/

	syslog(LOG_USER | LOG_INFO, "Handling client connection...\n");
	/* re-open debug log */
	ido2db_close_debug_log();
	ido2db_open_debug_log();

	/* reset signal handling */
	signal(SIGQUIT, ido2db_child_sighandler);
	signal(SIGTERM, ido2db_child_sighandler);
	signal(SIGINT, ido2db_child_sighandler);
	signal(SIGSEGV, ido2db_child_sighandler);
	signal(SIGFPE, ido2db_child_sighandler);

	/*
	 *initialize input data information
	 */
	ido2db_idi_init(&idi);

	/*
	 *********************************************************************
	 * thread initialization
	 *********************************************************************
	 */

	/*
	 * create cleaner thread
	 */
	if ((pthread_ret = pthread_create(&thread_pool[IDO2DB_THREAD_POOL_CLEANER], NULL, ido2db_thread_cleanup, &idi)) != 0) {
		syslog(LOG_ERR, "Could not create cleanup thread... exiting with error '%s'\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

        /* initialize data sink buffer */ 
        ido2db_sink_buffer_init(&sinkbuf, ido2db_sink_buffer_slots);

        /* read unprocessed data from buffer file */
        ido2db_load_unprocessed_data(&sinkbuf, ido2db_buffer_file); /* FIXME do we want that? */


	/* initialize sink buffer and log mutex */
        pthread_mutex_init(&sinkbuf.buffer_lock, NULL);
        pthread_mutex_init(&log_lock, NULL);

        /* create the queue thread and let it poll all data from the sink */
        result = pthread_create(&queue_thread, NULL, ido2db_read_from_sink_queue, &idi);

        if (result) {
		syslog(LOG_ERR, "Could not create queue thread... exiting with error '%s'\n", strerror(errno));
		exit(EXIT_FAILURE);
        }

	/* 
	 * create the dbqueue buffer and its mutex
	 */
	/* TODO queue buffer init, mutex init */
	ido2db_dbqueue_buf_init(&dbqueue_buf, ido2db_sink_buffer_slots);
	pthread_mutex_init(&dbqueue_buf.buffer_lock, NULL);

	/* create the db queue threads, which use their own asynchronous db connection */
	/* TODO - allow users to configure thread count */

	/* 
	 * first copy needed information into thread_data,
	 * this includes a unique thread identifier
	 * (pthred_self() is not usable!)
	 * then create the threads and save their handles
	 * we will use idi_thread_id for connect to db and such
	 */

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() dbqueue threads\n");

	/*
	 * set the unix thread with system scope
	 * for best performance
	 */
	pthread_attr_init(&attr_dbqueue);
	pthread_attr_setscope(&attr_dbqueue, PTHREAD_SCOPE_SYSTEM);

	thread_data->idi_thread_id = 0;
	thread_data->idi = NULL;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() dbqueue threads after init\n");
	thread_data->idi = &idi;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() dbqueue threads\n");

	for (t = 0; t < IDO2DB_DBQUEUE_THREADS; t++) { 
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() thread cnt %d\n", t);
		/*
		 * save the array identifier for this thread and pass it
		 * this will allow us to manage idi objects
		 */
		thread_data->idi_thread_id = t;
		/* 
		 * initialize idi and connect to db before threads are starting
		 */
		ido2db_dbqueue_thread_init(&idi, &dbqueue_idi[t], t);
		/*
		 * now actually create the threads and sleep a bit
		 */
		pthread_create(&dbqueue_thread[t], &attr_dbqueue, ido2db_dbqueue_handle, (void *)thread_data);

		delay.tv_sec = 0;
		delay.tv_nsec = 500;
		nanosleep(&delay, NULL);
	}

	pthread_attr_destroy(&attr_dbqueue);

	/*
	 *********************************************************************
	 * main initialization
	 *********************************************************************
	 */

	/* initialize dynamic buffer (2KB chunk size) */
	ido_dbuf_init(&dbuf, dbuf_chunk);

	/* initialize database connection */
	ido2db_db_init(&idi);

	/* check if connection to database was successful */
	if (ido2db_db_connect(&idi) == IDO_ERROR) {
		if (idi.dbinfo.connected != IDO_TRUE) {

			/* we did not get a db connection and the client should be disconnected */
			syslog(LOG_USER | LOG_INFO, "Error: database connection failed, forced client disconnect...\n");
			ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() idi.dbinfo.connected is '%d'\n", idi.dbinfo.connected);

			/* terminate threads */
			/*terminate_worker_thread();*/
			terminate_cleanup_thread();

			/* free memory allocated to dynamic buffer */
			ido_dbuf_free(&dbuf);

			/* reset db credentials */
			ido2db_db_deinit(&idi);

			/* free memory */
			ido2db_free_input_memory(&idi);
			ido2db_free_connection_memory(&idi);

			/* return error signalling that child is terminating */
			return IDO_ERROR;
		}
	}

#ifdef HAVE_SSL
	if (use_ssl == IDO_TRUE) {
		if ((ssl = SSL_new(ctx)) != NULL) {

			SSL_set_fd(ssl, sd);

			/* keep attempting the request if needed */
			while (((result = SSL_accept(ssl)) != 1) && (SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ));

			if (result != 1) {
				syslog(LOG_ERR, "Error: Could not complete SSL handshake. %d\n", SSL_get_error(ssl, result));

				return IDO_ERROR;
			}
		}
	}
#endif

	/* read all data from client */
	while (1) {
#ifdef HAVE_SSL
		if (use_ssl == IDO_FALSE)
			result = read(sd, buf, sizeof(buf) - 1);
		else {
			result = SSL_read(ssl, buf, sizeof(buf) - 1);
			if (result == -1 && (SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ)) {
				syslog(LOG_ERR, "SSL read error\n");
			}
		}
#else
		result = read(sd, buf, sizeof(buf) - 1);
#endif

		/* bail out on hard errors */
		if (result == -1) {
			/* EAGAIN and EINTR are soft errors, so try another read() */
			if (errno == EAGAIN || errno == EINTR)
				continue;
			else {
				error = IDO_TRUE;
#ifdef HAVE_SSL
				if (ssl) {
					SSL_shutdown(ssl);
					SSL_free(ssl);
					syslog(LOG_INFO, "INFO: SSL Socket Shutdown.\n");
				}
#endif
				break;
			}
		}

		/* zero bytes read means we lost the connection with the client */
		if (result == 0) {
#ifdef HAVE_SSL
			if (ssl) {
				SSL_shutdown(ssl);
				SSL_free(ssl);
				syslog(LOG_INFO, "INFO: SSL Socket Shutdown.\n");
			}
#endif

			/* gracefully back out of current operation... */
			ido2db_db_goodbye(&idi);

			break;
		}

#ifdef DEBUG_IDO2DB2
		printf("BYTESREAD: %d\n", result);
#endif

		/* append data we just read to dynamic buffer */
		buf[result] = '\x0';
		/* 2011-02-23 MF: lock dynamic buffer with a mutex when writing */
		/* 2011-07-22 MF: redo it the old way, it may cause dead locks */
		/* pthread_mutex_lock(&ido2db_dbuf_lock); */
		ido_dbuf_strcat(&dbuf, buf);
		/* pthread_mutex_unlock(&ido2db_dbuf_lock); */

		/* check for completed lines of input */
		/* 2011-02-23 MF: only do that in a worker thread */
		/* 2011-05-02 MF: redo it the old way */

		ido2db_check_for_client_input(&idi);


		/* should we disconnect the client? */
		if (idi.disconnect_client == IDO_TRUE) {

			/* gracefully back out of current operation... */
			ido2db_db_goodbye(&idi);

			break;
		}
	}

#ifdef DEBUG_IDO2DB2
	printf("BYTES: %lu, LINES: %lu\n", idi.bytes_processed, idi.lines_processed);
#endif

        /* save unprocessed data to buffer file */
        ido2db_save_unprocessed_data(&sinkbuf, ido2db_buffer_file);

	/* terminate threads */
	ido2db_terminate_threads();

	/* free memory allocated to dynamic buffer */
	ido_dbuf_free(&dbuf);

        /* clear sink buffer */
        ido2db_sink_buffer_deinit(&sinkbuf);

        /* clear dbqueue buffer */
        ido2db_dbqueue_buf_deinit(&dbqueue_buf);

	/* disconnect threads from database */
	ido2db_disconnect_threads();

	/* disconnect from database */
	ido2db_db_disconnect(&idi);
	ido2db_db_deinit(&idi);

	/* free memory */
	ido2db_free_input_memory(&idi);
	ido2db_free_connection_memory(&idi);

	/* close syslog facility */
	/*closelog();*/

	if (error == IDO_TRUE)
		return IDO_ERROR;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_connection() end\n");

	return IDO_OK;
}

/* initializes structure for tracking data */
int ido2db_idi_init_mbuf(ido2db_idi *idi) {
	int x = 0;

        if (idi == NULL)
                return IDO_ERROR;

        /* initialize mbuf */
        for (x = 0; x < IDO2DB_MAX_MBUF_ITEMS; x++) {
                idi->mbuf[x].used_lines = 0;
                idi->mbuf[x].allocated_lines = 0;
                idi->mbuf[x].buffer = NULL;
        }

        return IDO_OK;
}



/* initializes structure for tracking data */
int ido2db_idi_init(ido2db_idi *idi) {
	int x = 0;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_idi_init() start\n");

	if (idi == NULL)
		return IDO_ERROR;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_idi_init() prepare elements\n");

	idi->disconnect_client = IDO_FALSE;
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_idi_init() first element done\n");

	idi->ignore_client_data = IDO_FALSE;
	idi->protocol_version = 0;
	idi->instance_name = NULL;
	idi->buffered_input = NULL;
	idi->agent_name = NULL;
	idi->agent_version = NULL;
	idi->disposition = NULL;
	idi->connect_source = NULL;
	idi->connect_type = NULL;
	idi->current_input_section = IDO2DB_INPUT_SECTION_NONE;
	idi->current_input_data = IDO2DB_INPUT_DATA_NONE;
	idi->bytes_processed = 0L;
	idi->lines_processed = 0L;
	idi->entries_processed = 0L;
	idi->current_object_config_type = IDO2DB_CONFIGTYPE_ORIGINAL;
	idi->data_start_time = 0L;
	idi->data_end_time = 0L;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_idi_init() init mbuf\n");

	/* initialize mbuf */
	for (x = 0; x < IDO2DB_MAX_MBUF_ITEMS; x++) {
		idi->mbuf[x].used_lines = 0;
		idi->mbuf[x].allocated_lines = 0;
		idi->mbuf[x].buffer = NULL;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_idi_init() end\n");

	return IDO_OK;
}


/* checks for single lines of input from a client connection */
/* 2011-02-23 MF: called in worker thread */
/* 2011-05-02 MF: restructured sequential */
int ido2db_check_for_client_input(ido2db_idi *idi) {
	char *buf = NULL;
	register int x;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_for_client_input() start\n");

	/*	if(&dbuf==NULL)
			return IDO_OK;*/
	if (dbuf.buf == NULL)
		return IDO_OK;
	/* check if buffer full? bail out and tell main to disconnect the client! FIXME */
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_for_client_input() dbuf.size=%lu\n", dbuf.used_size);

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_for_client_input() ido2db_dbuf_lock start\n");

#ifdef DEBUG_IDO2DB2
	printf("RAWBUF: %s\n", dbuf.buf);
	printf("  USED1: %lu, BYTES: %lu, LINES: %lu\n", dbuf->used_size, idi->bytes_processed, idi->lines_processed);
#endif

	/* search for complete lines of input */
	for (x = 0; dbuf.buf[x] != '\x0'; x++) {

		/* we found the end of a line */
		if (dbuf.buf[x] == '\n') {

#ifdef DEBUG_IDO2DB2
			printf("BUF[%d]='\\n'\n", x);
#endif

			/* handle this line of input */
			dbuf.buf[x] = '\x0';

			if ((buf = strdup(dbuf.buf))) {

				//ido2db_handle_client_input(idi, buf);
				ido2db_write_to_sink_queue(buf);

				free(buf);
				buf = NULL;
				idi->lines_processed++;
				idi->bytes_processed += (x + 1);
			}

			/* shift data back to front of buffer and adjust counters */
			memmove((void *)&dbuf.buf[0], (void *)&dbuf.buf[x+1], (size_t)((int)dbuf.used_size - x - 1));
			dbuf.used_size -= (x + 1);
			dbuf.buf[dbuf.used_size] = '\x0';
			x = -1;
#ifdef DEBUG_IDO2DB2
			printf("  USED2: %lu, BYTES: %lu, LINES: %lu\n", dbuf.used_size, idi->bytes_processed, idi->lines_processed);
#endif
		}
	}

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_for_client_input() ido2db_dbuf_lock end\n");

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_check_for_client_input() end\n");

	return IDO_OK;
}

/* write data to queue from sink */
int ido2db_write_to_sink_queue(char *buf) {
        int buffer_items, head, tail = 0;
        struct timespec delay;
        int retry = 0;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_write_to_sink_queue() start\n");

        /* don't process empty buffer */
        if (buf == NULL)
                return IDO_ERROR;

        while(1) { /* we need looping in order to retry if buffer was full */

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_write_to_sink_queue() buf: %s\n", buf);

                /* get number of items in the buffer */
                pthread_mutex_lock(&sinkbuf.buffer_lock);
                buffer_items = sinkbuf.items;
                head = sinkbuf.head;
                tail = sinkbuf.tail;
                pthread_mutex_unlock(&sinkbuf.buffer_lock);

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_write_to_sink_queue() buffer items: %d/%d head: %d tail: %d\n", buffer_items, ido2db_sink_buffer_slots, head, tail);

                /* process all data if there's some space in the buffer */
                if (ido2db_sink_buffer_push(&sinkbuf, buf) == IDO_OK) {
                        /* write was successful, don't retry */
                        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_write_to_sink_queue() success\n");

                        /*
                         * We should wait for the sink queuing to catch up some data
                         * from the buffer if for this atomic run the buffer is filled completely or
                         * is overrun
                         */
                        /* wait a bit */
                        delay.tv_sec = 0;
                        delay.tv_nsec = 500000;
                        nanosleep(&delay, NULL);

                        return IDO_OK;

                } else {
                        /* write was not successful, retry */
                        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_write_to_sink_queue() no success, retry: %d/%d\n", retry, IDO2DB_SINK_RETRY_ON_ERROR);
                        retry++;
                }

                /*
                 * We should wait for the sink queuing to catch up some data
                 * from the buffer if for this atomic run the buffer is filled completely or
                 * is overrun
                 */
                /* wait a bit */
                delay.tv_sec = 0;
                delay.tv_nsec = 500000;
                nanosleep(&delay, NULL);

                /* don't retry too often */
                /* FIXME - this should be dumped to disk then */
                if (retry == IDO2DB_SINK_RETRY_ON_ERROR) {
                        //ido2db_write_to_logs("ido2db: Unable to write to buffer. Maybe increase output_buffer_items?\n", NSLOG_INFO_MESSAGE);
                        //break; /* FIXME we need to loop until the db is ready? */
                }

        }

        return IDO_OK;

}

void cleanup_queue_thread(void *arg) {

        /* sinkbuf cleanup happens in main thread, deinit module */
        return;
}


/* read data from queue for database as seperate consumer thread */
void * ido2db_read_from_sink_queue(void * data) {
        char *buffer = NULL;
        int result = 0;
        int buffer_items, head, tail = 0;
        struct timespec delay;

	ido2db_idi *idi = (ido2db_idi*) data;

        /* specify cleanup routine */
        pthread_cleanup_push(cleanup_queue_thread, NULL);

        /* set cancellation info */
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_read_from_sink_queue() started with thread id %ld\n", pthread_self());

        while (1) {

                /* get number of items in the buffer */
                pthread_mutex_lock(&sinkbuf.buffer_lock);
                buffer_items = sinkbuf.items;
                head = sinkbuf.head;
                tail = sinkbuf.tail;
                pthread_mutex_unlock(&sinkbuf.buffer_lock);

                /* make sure we shouldn't bail out early */
                pthread_testcancel();

                /* if no items present, continue looping */
                if (buffer_items == 0) {
                        delay.tv_sec = 0;
                        delay.tv_nsec = 50000;
                        nanosleep(&delay, NULL);
                        continue;
                }

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_read_from_sink_queue() buffer items: %d/%d head: %d tail: %d\n", buffer_items, ido2db_sink_buffer_slots, head, tail);

                buffer = ido2db_sink_buffer_pop(&sinkbuf);

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_read_from_sink_queue() buffer: %s\n", buffer);

                /* write the data to database processing */
		result = ido2db_handle_client_input(idi, buffer);

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_read_from_sink_queue() write_to_sink result: %d\n", result);

                /* free memory */
                my_free(buffer);

                /* wait a bit */
                delay.tv_sec = 0;
                delay.tv_nsec = 50000;
                nanosleep(&delay, NULL);
        }

        /* removes cleanup handler - this should never be reached */
        pthread_cleanup_pop(0);

}

/* handles a single line of input from a client connection */
int ido2db_handle_client_input(ido2db_idi *idi, char *buf) {
	char *var = NULL;
	char *val = NULL;
	unsigned long data_type_long = 0L;
	int data_type = IDO_DATA_NONE;
	int input_type = IDO2DB_INPUT_DATA_NONE;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_input(instance_name=%s) start\n", idi->instance_name);

#ifdef DEBUG_IDO2DB2
	printf("HANDLING: '%s'\n", buf);
#endif

	if (buf == NULL || idi == NULL)
		return IDO_ERROR;

	/* we're ignoring client data because of wrong protocol version, etc...  */
	if (idi->ignore_client_data == IDO_TRUE)
		return IDO_ERROR;

	/* skip empty lines */
	if (buf[0] == '\x0')
		return IDO_OK;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_input() input_section\n");

	switch (idi->current_input_section) {

	case IDO2DB_INPUT_SECTION_NONE:

		var = strtok(buf, ":");
		val = strtok(NULL, "\n");

		if (!strcmp(var, IDO_API_HELLO)) {

			idi->current_input_section = IDO2DB_INPUT_SECTION_HEADER;
			idi->current_input_data = IDO2DB_INPUT_DATA_NONE;

			/* free old connection memory (necessary in some cases) */
			ido2db_free_connection_memory(idi);
		}

		break;

	case IDO2DB_INPUT_SECTION_HEADER:

		var = strtok(buf, ":");
		val = strtok(NULL, "\n");

		if (!strcmp(var, IDO_API_STARTDATADUMP)) {

			/* client is using wrong protocol version, bail out here... */
			if (idi->protocol_version != IDO_API_PROTOVERSION) {
				syslog(LOG_USER | LOG_INFO, "Error: Client protocol version %d is incompatible with server version %d.  Disconnecting client...", idi->protocol_version, IDO_API_PROTOVERSION);
				idi->disconnect_client = IDO_TRUE;
				idi->ignore_client_data = IDO_TRUE;
				return IDO_ERROR;
			}

			idi->current_input_section = IDO2DB_INPUT_SECTION_DATA;

			/* save connection info to DB */
			ido2db_db_hello(idi);

		}

		else if (!strcmp(var, IDO_API_PROTOCOL))
			ido2db_convert_string_to_int((val + 1), &idi->protocol_version);

		else if (!strcmp(var, IDO_API_INSTANCENAME))
			idi->instance_name = strdup(val + 1);

		else if (!strcmp(var, IDO_API_AGENT))
			idi->agent_name = strdup(val + 1);

		else if (!strcmp(var, IDO_API_AGENTVERSION))
			idi->agent_version = strdup(val + 1);

		else if (!strcmp(var, IDO_API_DISPOSITION))
			idi->disposition = strdup(val + 1);

		else if (!strcmp(var, IDO_API_CONNECTION))
			idi->connect_source = strdup(val + 1);

		else if (!strcmp(var, IDO_API_CONNECTTYPE))
			idi->connect_type = strdup(val + 1);

		else if (!strcmp(var, IDO_API_STARTTIME))
			ido2db_convert_string_to_unsignedlong((val + 1), &idi->data_start_time);

		break;

	case IDO2DB_INPUT_SECTION_FOOTER:

		var = strtok(buf, ":");
		val = strtok(NULL, "\n");

		/* client is saying goodbye... */
		if (!strcmp(var, IDO_API_GOODBYE))
			idi->current_input_section = IDO2DB_INPUT_SECTION_NONE;

		else if (!strcmp(var, IDO_API_ENDTIME))
			ido2db_convert_string_to_unsignedlong((val + 1), &idi->data_end_time);

		break;

	case IDO2DB_INPUT_SECTION_DATA:

		if (idi->current_input_data == IDO2DB_INPUT_DATA_NONE) {

			var = strtok(buf, ":");
			val = strtok(NULL, "\n");

			input_type = atoi(var);

			switch (input_type) {

				/* we're reached the end of all of the data... */
			case IDO_API_ENDDATADUMP:
				idi->current_input_section = IDO2DB_INPUT_SECTION_FOOTER;
				idi->current_input_data = IDO2DB_INPUT_DATA_NONE;
				break;

				/* config dumps */
			case IDO_API_STARTCONFIGDUMP:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONFIGDUMPSTART;
				break;
			case IDO_API_ENDCONFIGDUMP:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONFIGDUMPEND;
				break;

				/* archived data */
			case IDO_API_LOGENTRY:
				idi->current_input_data = IDO2DB_INPUT_DATA_LOGENTRY;
				break;

				/* realtime data */
			case IDO_API_PROCESSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_PROCESSDATA;
				break;
			case IDO_API_TIMEDEVENTDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_TIMEDEVENTDATA;
				break;
			case IDO_API_LOGDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_LOGDATA;
				break;
			case IDO_API_SYSTEMCOMMANDDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_SYSTEMCOMMANDDATA;
				break;
			case IDO_API_EVENTHANDLERDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_EVENTHANDLERDATA;
				break;
			case IDO_API_NOTIFICATIONDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_NOTIFICATIONDATA;
				break;
			case IDO_API_SERVICECHECKDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICECHECKDATA;
				break;
			case IDO_API_HOSTCHECKDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTCHECKDATA;
				break;
			case IDO_API_COMMENTDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_COMMENTDATA;
				break;
			case IDO_API_DOWNTIMEDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_DOWNTIMEDATA;
				break;
			case IDO_API_FLAPPINGDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_FLAPPINGDATA;
				break;
			case IDO_API_PROGRAMSTATUSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_PROGRAMSTATUSDATA;
				break;
			case IDO_API_HOSTSTATUSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTSTATUSDATA;
				break;
			case IDO_API_SERVICESTATUSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICESTATUSDATA;
				break;
			case IDO_API_CONTACTSTATUSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONTACTSTATUSDATA;
				break;
			case IDO_API_ADAPTIVEPROGRAMDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_ADAPTIVEPROGRAMDATA;
				break;
			case IDO_API_ADAPTIVEHOSTDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_ADAPTIVEHOSTDATA;
				break;
			case IDO_API_ADAPTIVESERVICEDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_ADAPTIVESERVICEDATA;
				break;
			case IDO_API_ADAPTIVECONTACTDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_ADAPTIVECONTACTDATA;
				break;
			case IDO_API_EXTERNALCOMMANDDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_EXTERNALCOMMANDDATA;
				break;
			case IDO_API_AGGREGATEDSTATUSDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_AGGREGATEDSTATUSDATA;
				break;
			case IDO_API_RETENTIONDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_RETENTIONDATA;
				break;
			case IDO_API_CONTACTNOTIFICATIONDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONTACTNOTIFICATIONDATA;
				break;
			case IDO_API_CONTACTNOTIFICATIONMETHODDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONTACTNOTIFICATIONMETHODDATA;
				break;
			case IDO_API_ACKNOWLEDGEMENTDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_ACKNOWLEDGEMENTDATA;
				break;
			case IDO_API_STATECHANGEDATA:
				idi->current_input_data = IDO2DB_INPUT_DATA_STATECHANGEDATA;
				break;

				/* config variables */
			case IDO_API_MAINCONFIGFILEVARIABLES:
				idi->current_input_data = IDO2DB_INPUT_DATA_MAINCONFIGFILEVARIABLES;
				break;
			case IDO_API_RESOURCECONFIGFILEVARIABLES:
				idi->current_input_data = IDO2DB_INPUT_DATA_RESOURCECONFIGFILEVARIABLES;
				break;
			case IDO_API_CONFIGVARIABLES:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONFIGVARIABLES;
				break;
			case IDO_API_RUNTIMEVARIABLES:
				idi->current_input_data = IDO2DB_INPUT_DATA_RUNTIMEVARIABLES;
				break;

				/* object configuration */
			case IDO_API_HOSTDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTDEFINITION;
				break;
			case IDO_API_HOSTGROUPDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTGROUPDEFINITION;
				break;
			case IDO_API_SERVICEDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICEDEFINITION;
				break;
			case IDO_API_SERVICEGROUPDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICEGROUPDEFINITION;
				break;
			case IDO_API_HOSTDEPENDENCYDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTDEPENDENCYDEFINITION;
				break;
			case IDO_API_SERVICEDEPENDENCYDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICEDEPENDENCYDEFINITION;
				break;
			case IDO_API_HOSTESCALATIONDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_HOSTESCALATIONDEFINITION;
				break;
			case IDO_API_SERVICEESCALATIONDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_SERVICEESCALATIONDEFINITION;
				break;
			case IDO_API_COMMANDDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_COMMANDDEFINITION;
				break;
			case IDO_API_TIMEPERIODDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_TIMEPERIODDEFINITION;
				break;
			case IDO_API_CONTACTDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONTACTDEFINITION;
				break;
			case IDO_API_CONTACTGROUPDEFINITION:
				idi->current_input_data = IDO2DB_INPUT_DATA_CONTACTGROUPDEFINITION;
				break;
			case IDO_API_HOSTEXTINFODEFINITION:
				/* deprecated - merged with host definitions */
			case IDO_API_SERVICEEXTINFODEFINITION:
				/* deprecated - merged with service definitions */
			default:
				break;
			}

			/* initialize input data */
			ido2db_start_input_data(idi);
		}

		/* we are processing some type of data already... */
		else {

			var = strtok(buf, "=");
			val = strtok(NULL, "\n");

			/* get the data type */
			data_type_long = strtoul(var, NULL, 0);

			/* there was an error with the data type - throw it out */
			if (data_type_long == ULONG_MAX && errno == ERANGE)
				break;

			data_type = (int)data_type_long;

			/* the current data section is ending... */
			if (data_type == IDO_API_ENDDATA) {

				/* finish current data processing */
				ido2db_end_input_data(idi);

				idi->current_input_data = IDO2DB_INPUT_DATA_NONE;
			}

			/* add data for already existing data type... */
			else {

				/* the data type is out of range - throw it out */
				if (data_type > IDO_MAX_DATA_TYPES) {
					ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_input() line: %lu, type: %d, VAL: %s\n", idi->lines_processed, data_type, (val == NULL) ? "" : val);
#ifdef DEBUG_IDO2DB2
					printf("## DISCARD! LINE: %lu, TYPE: %d, VAL: %s\n", idi->lines_processed, data_type, val);
#endif
					break;
				}

				ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_input() line: %lu, type: %d, VAL: %s\n", idi->lines_processed, data_type, (val == NULL) ? "" : val);
#ifdef DEBUG_IDO2DB2
				printf("LINE: %lu, TYPE: %d, VAL:%s\n", idi->lines_processed, data_type, val);
#endif
				ido2db_add_input_data_item(idi, data_type, val);
			}
		}

		break;

	default:
		break;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_client_input() end\n");
	return IDO_OK;
}


int ido2db_start_input_data(ido2db_idi *idi) {
	int x;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_start_input_data() start\n");

	if (idi == NULL)
		return IDO_ERROR;

	/* sometimes ido2db_end_input_data() isn't called, so free memory if we find it */
	/* disable that as it interferes with threading */
	/*ido2db_free_input_memory(idi);*/

	/* allocate memory for holding buffered input */
	if ((idi->buffered_input = (char **)malloc(sizeof(char *) * IDO_MAX_DATA_TYPES)) == NULL)
		return IDO_ERROR;

	/* initialize buffered input slots */
	for (x = 0; x < IDO_MAX_DATA_TYPES; x++)
		idi->buffered_input[x] = NULL;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_start_input_data() end\n");

	return IDO_OK;
}


int ido2db_add_input_data_item(ido2db_idi *idi, int type, char *buf) {
	char *newbuf = NULL;
	int mbuf_used = IDO_TRUE;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_add_input_data_item() start\n");

	if (idi == NULL)
		return IDO_ERROR;

	/* escape data if necessary */
	switch (type) {

	case IDO_DATA_ACKAUTHOR:
	case IDO_DATA_ACKDATA:
	case IDO_DATA_AUTHORNAME:
	case IDO_DATA_CHECKCOMMAND:
	case IDO_DATA_COMMANDARGS:
	case IDO_DATA_COMMANDLINE:
	case IDO_DATA_COMMANDSTRING:
	case IDO_DATA_COMMENT:
	case IDO_DATA_EVENTHANDLER:
	case IDO_DATA_GLOBALHOSTEVENTHANDLER:
	case IDO_DATA_GLOBALSERVICEEVENTHANDLER:
	case IDO_DATA_HOST:
	case IDO_DATA_LOGENTRY:
	case IDO_DATA_OUTPUT:
	case IDO_DATA_LONGOUTPUT:
	case IDO_DATA_PERFDATA:
	case IDO_DATA_SERVICE:
	case IDO_DATA_PROGRAMNAME:
	case IDO_DATA_PROGRAMVERSION:
	case IDO_DATA_PROGRAMDATE:

	case IDO_DATA_COMMANDNAME:
	case IDO_DATA_CONTACTADDRESS:
	case IDO_DATA_CONTACTALIAS:
	case IDO_DATA_CONTACTGROUP:
	case IDO_DATA_CONTACTGROUPALIAS:
	case IDO_DATA_CONTACTGROUPMEMBER:
	case IDO_DATA_CONTACTGROUPNAME:
	case IDO_DATA_CONTACTNAME:
	case IDO_DATA_DEPENDENTHOSTNAME:
	case IDO_DATA_DEPENDENTSERVICEDESCRIPTION:
	case IDO_DATA_DISPLAYNAME:
	case IDO_DATA_EMAILADDRESS:
	case IDO_DATA_HOSTADDRESS:
	case IDO_DATA_HOSTADDRESS6:
	case IDO_DATA_HOSTALIAS:
	case IDO_DATA_HOSTCHECKCOMMAND:
	case IDO_DATA_HOSTCHECKPERIOD:
	case IDO_DATA_HOSTEVENTHANDLER:
	case IDO_DATA_HOSTFAILUREPREDICTIONOPTIONS:
	case IDO_DATA_HOSTGROUPALIAS:
	case IDO_DATA_HOSTGROUPMEMBER:
	case IDO_DATA_HOSTGROUPNAME:
	case IDO_DATA_HOSTNAME:
	case IDO_DATA_HOSTNOTIFICATIONCOMMAND:
	case IDO_DATA_HOSTNOTIFICATIONPERIOD:
	case IDO_DATA_PAGERADDRESS:
	case IDO_DATA_PARENTHOST:
	case IDO_DATA_SERVICECHECKCOMMAND:
	case IDO_DATA_SERVICECHECKPERIOD:
	case IDO_DATA_SERVICEDESCRIPTION:
	case IDO_DATA_SERVICEEVENTHANDLER:
	case IDO_DATA_SERVICEFAILUREPREDICTIONOPTIONS:
	case IDO_DATA_SERVICEGROUPALIAS:
	case IDO_DATA_SERVICEGROUPMEMBER:
	case IDO_DATA_SERVICEGROUPNAME:
	case IDO_DATA_SERVICENOTIFICATIONCOMMAND:
	case IDO_DATA_SERVICENOTIFICATIONPERIOD:
	case IDO_DATA_TIMEPERIODALIAS:
	case IDO_DATA_TIMEPERIODNAME:
	case IDO_DATA_TIMERANGE:

	case IDO_DATA_ACTIONURL:
	case IDO_DATA_ICONIMAGE:
	case IDO_DATA_ICONIMAGEALT:
	case IDO_DATA_NOTES:
	case IDO_DATA_NOTESURL:
	case IDO_DATA_CUSTOMVARIABLE:
	case IDO_DATA_CONTACT:

		/* strings are escaped when they arrive */
		if (buf == NULL)
			newbuf = strdup("");
		else
			newbuf = strdup(buf);
		ido_unescape_buffer(newbuf);
		break;

	default:

		/* data hasn't been escaped */
		if (buf == NULL)
			newbuf = strdup("");
		else
			newbuf = strdup(buf);
		break;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_add_input_data_item(%s)\n", (newbuf == NULL) ? "" : newbuf);

	/* check for errors */
	if (newbuf == NULL) {
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_add_input_data_item() allocation error\n");
#ifdef DEBUG_IDO2DB
		printf("ALLOCATION ERROR\n");
#endif
		return IDO_ERROR;
	}

	/* store the buffered data */
	switch (type) {

		/* special case for data items that may appear multiple times */
	case IDO_DATA_CONTACTGROUP:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONTACTGROUP, newbuf);
		break;
	case IDO_DATA_CONTACTGROUPMEMBER:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONTACTGROUPMEMBER, newbuf);
		break;
	case IDO_DATA_SERVICEGROUPMEMBER:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_SERVICEGROUPMEMBER, newbuf);
		break;
	case IDO_DATA_HOSTGROUPMEMBER:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_HOSTGROUPMEMBER, newbuf);
		break;
	case IDO_DATA_SERVICENOTIFICATIONCOMMAND:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_SERVICENOTIFICATIONCOMMAND, newbuf);
		break;
	case IDO_DATA_HOSTNOTIFICATIONCOMMAND:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_HOSTNOTIFICATIONCOMMAND, newbuf);
		break;
	case IDO_DATA_CONTACTADDRESS:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONTACTADDRESS, newbuf);
		break;
	case IDO_DATA_TIMERANGE:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_TIMERANGE, newbuf);
		break;
	case IDO_DATA_PARENTHOST:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_PARENTHOST, newbuf);
		break;
	case IDO_DATA_CONFIGFILEVARIABLE:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONFIGFILEVARIABLE, newbuf);
		break;
	case IDO_DATA_CONFIGVARIABLE:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONFIGVARIABLE, newbuf);
		break;
	case IDO_DATA_RUNTIMEVARIABLE:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_RUNTIMEVARIABLE, newbuf);
		break;
	case IDO_DATA_CUSTOMVARIABLE:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CUSTOMVARIABLE, newbuf);
		break;
	case IDO_DATA_CONTACT:
		ido2db_add_input_data_mbuf(idi, type, IDO2DB_MBUF_CONTACT, newbuf);
		break;

		/* NORMAL DATA */
		/* normal data items appear only once per data type */
	default:

		mbuf_used = IDO_FALSE;

		/* if there was already a matching item, discard the old one */
		if (idi->buffered_input[type] != NULL) {
			free(idi->buffered_input[type]);
			idi->buffered_input[type] = NULL;
		}

		/* save buffered item */
		idi->buffered_input[type] = newbuf;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_start_input_data() end\n");
	return IDO_OK;
}



int ido2db_add_input_data_mbuf(ido2db_idi *idi, int type, int mbuf_slot, char *buf) {
	int allocation_chunk = 80;
	char **newbuffer = NULL;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_add_input_data_mbuf() start\n");

	if (idi == NULL || buf == NULL)
		return IDO_ERROR;

	if (mbuf_slot >= IDO2DB_MAX_MBUF_ITEMS)
		return IDO_ERROR;

	/* create buffer */
	if (idi->mbuf[mbuf_slot].buffer == NULL) {
#ifdef IDO2DB_DEBUG_MBUF
		mbuf_bytes_allocated += sizeof(char *) * allocation_chunk;
		printf("MBUF INITIAL ALLOCATION (MBUF = %lu bytes)\n", mbuf_bytes_allocated);
#endif
		idi->mbuf[mbuf_slot].buffer = (char **)malloc(sizeof(char *) * allocation_chunk);
		idi->mbuf[mbuf_slot].allocated_lines += allocation_chunk;
	}

	/* expand buffer */
	if (idi->mbuf[mbuf_slot].used_lines == idi->mbuf[mbuf_slot].allocated_lines) {
		newbuffer = (char **)realloc(idi->mbuf[mbuf_slot].buffer, sizeof(char *) * (idi->mbuf[mbuf_slot].allocated_lines + allocation_chunk));
		if (newbuffer == NULL)
			return IDO_ERROR;
#ifdef IDO2DB_DEBUG_MBUF
		mbuf_bytes_allocated += sizeof(char *) * allocation_chunk;
		printf("MBUF RESIZED (MBUF = %lu bytes)\n", mbuf_bytes_allocated);
#endif
		idi->mbuf[mbuf_slot].buffer = newbuffer;
		idi->mbuf[mbuf_slot].allocated_lines += allocation_chunk;
	}

	/* store the data */
	if (idi->mbuf[mbuf_slot].buffer) {
		idi->mbuf[mbuf_slot].buffer[idi->mbuf[mbuf_slot].used_lines] = buf;
		idi->mbuf[mbuf_slot].used_lines++;
	} else
		return IDO_ERROR;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_add_input_data_mbuf() end\n");
	return IDO_OK;
}


/* TODO 
 *
 * this function only handles the end of the input data, 
 * where the buffered_input and mbuf are ready
 * to be processed. 
 * therefore pointers are saved and pushed to dbqueue
 */
int ido2db_end_input_data(ido2db_idi *idi) {
        int buffer_items, head, tail = 0;
        struct timespec delay;
        int retry = 0;
	int result = IDO_OK;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_end_input_data() start\n");

	if (idi == NULL)
		return IDO_ERROR;

	/* TODO
	 * push the idi object holding all buffers into the queue
	 * after locking the mutex for dbqueue
	 * the item is reassigned the pointers
	 * and stored to the buffer, then releasing the mutex lock
	 * TODO maybe do some cleanup on the idi object itsself afterwards?
	 * attention - we pass a pointer!
	 */
	
	/*
	 * loop to get all items pushed, i.e. buffer full
	 */
        while(1) {

                /* get number of items in the buffer */
                pthread_mutex_lock(&dbqueue_buf.buffer_lock);
                buffer_items = dbqueue_buf.items;
                head = dbqueue_buf.head;
                tail = dbqueue_buf.tail;
                pthread_mutex_unlock(&dbqueue_buf.buffer_lock);

                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_end_input_data() buffer items: %d/%d head: %d tail: %d\n", buffer_items, ido2db_dbqueue_buf_slots, head, tail);

                /* 
		 * push idi object onto the dbqueue_buf
		 * inner push functionality will take care
		 * of all struct items
		 * if not successful, loop again retrying
		 */
                if (ido2db_dbqueue_buf_push(&dbqueue_buf, idi) == IDO_OK) {
                        /* write was successful, don't retry */
                        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_end_input_data() dbqueue_buf push success\n");

                        /*
                         * We should wait for the sink queuing to catch up some data
                         * from the buffer if for this atomic run the buffer is filled completely or
                         * is overrun
                         */
                        /* wait a bit */
                        delay.tv_sec = 0;
                        delay.tv_nsec = 500000;
                        nanosleep(&delay, NULL);

                        return IDO_OK;

                } else {
                        /* write was not successful, retry */
                        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_end_input_data() no dbqueue_buf push success, retry: %d/%d\n", retry, IDO2DB_SINK_RETRY_ON_ERROR);
                        retry++;
                }

                /*
                 * We should wait for the sink queuing to catch up some data
                 * from the buffer if for this atomic run the buffer is filled completely or
                 * is overrun
                 */
                /* wait a bit */
                delay.tv_sec = 0;
                delay.tv_nsec = 500000;
                nanosleep(&delay, NULL);

                /* don't retry too often */
                /* FIXME - this should be dumped to disk then */
                if (retry == IDO2DB_DBQUEUE_RETRY_ON_ERROR) {
                        //ido2db_write_to_logs("ido2db: Unable to write to buffer. Maybe increase output_buffer_items?\n", NSLOG_INFO_MESSAGE);
                        //break; /* FIXME we need to loop until the db is ready? */
                }

        }

        return IDO_OK;
}



/* DBQUEUE */

/*
 * we will call this in main thread
 * in order to control the connection
 * flow, because at least mysql driver
 * is not threadsafe on libdbi
 */
int ido2db_dbqueue_thread_init(ido2db_idi *idi, ido2db_idi *dbqueue_idi, int idi_thread_id) {
        char *temp_buffer;

        /* initialize input data information */
        ido2db_idi_init(dbqueue_idi);

        /* initialize database connection */
        ido2db_db_init(dbqueue_idi);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_thread_init() after db_init\n");

        /* copy needed idi information */
        dummy = asprintf(&temp_buffer, "IDO2DB DBQueue ID %d", idi_thread_id);
        dbqueue_idi->instance_name = idi->instance_name;
        dbqueue_idi->agent_name = strdup(temp_buffer); /* create a copy and free it locally to avoid leaks */
        dbqueue_idi->agent_version = idi->agent_version;
        dbqueue_idi->disposition = idi->disposition;
        dbqueue_idi->connect_source = idi->connect_source;
        dbqueue_idi->connect_type = idi->connect_type;
        my_free(temp_buffer);

        /* FIXME TODO
         * now connect to database
         */
        if (ido2db_db_connect(dbqueue_idi) == IDO_ERROR) {

                /* tell main process to disconnect */
                idi->disconnect_client = IDO_TRUE;

                /* cleanup the thread */
                ido2db_db_deinit(dbqueue_idi);

                /* free memory */
                ido2db_free_input_memory(dbqueue_idi);
                ido2db_free_connection_memory(dbqueue_idi);

                return IDO_ERROR;
        }

	return IDO_OK;
}


void * ido2db_dbqueue_handle(void *data) {
        int buffer_items, head, tail = 0;
        struct timespec delay;
        int retry = 0;
        int dummy;
	int result = IDO_OK;

        unsigned long int idi_thread_id;
        ido2db_thread_data *thread_data = (ido2db_thread_data*) data;
	ido2db_idi *idi;

        /*
         * first get the idi_thread_id 
         * this will help us work on different
         * idi objects with db connections
         */
        idi_thread_id = thread_data->idi_thread_id;
	idi = thread_data->idi;

        delay.tv_sec = 0;
        delay.tv_nsec = 5000;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_handle() start idi_thread_id %d\n", idi_thread_id);

        /* set cancellation info */
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

        /* specify cleanup routine */
        pthread_cleanup_push((void *) &ido2db_thread_dbqueue_exit_handler, NULL);

	/*
	 * idi and db connection was done
	 * before in main thread before
	 * thread creation due to possible
	 * race conditions on the mysql driver
	 * 2019: Can't initialize character set latin1 (path: /usr/share/mysql/charsets/)
	 */

        /* TODO wait until instance_name set to say hello to the db */
        /* main idi object holds idi->instance_name and idi->instance_id which are unique identifiers
         * to multiple idomod client connections
         * we need to make sure that this data is inserted with ido2db_db_hello before
         * doing any other operation on further data processing
         * 
         * since this is done outside the IDO_START_DATADUMP, but in the SECTION_HEADER after reading
         * all information like instance_name, we just idle here if the thread dbhello does not return
         * ok. this function is modified not to insert any instance if not found, but just to check for
         * an existing entry
         */

        /* save connection info to DB */
        while (ido2db_thread_db_hello(&dbqueue_idi[idi_thread_id]) == IDO_ERROR) {
                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_handle(idi_thread_id=%d) no instance found, sleeping...\n", idi_thread_id);
                /* don't hogg the cpu */
                nanosleep(&delay, NULL);
        }
        /* XXX recheck if we now have an instance_id ? */

	/*
	 * now loop to fetch all items from dbqueue
	 */
        while (1) {

                /* should we shutdown? */
                pthread_testcancel();

                /*
                 * if the main process was required to shutdown, threads will terminate too
                 */
                if (idi->disconnect_client == IDO_TRUE) {
                        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_handle(): origin idi said we should disconnect the client\n");
                        break;
                }

		/*
		 * we do the pointer reassign to idi object
		 * stuff within the pop function, because
		 * there we already have a lock on the buffer
		 * the idi object will be updated after
		 * actually pop'ing from the dbqueue_buf
		 * attention - idi is a pointer.
		 */
		result = ido2db_dbqueue_buf_pop(&dbqueue_buf, &dbqueue_idi[idi_thread_id]);

		/*
		 * we check if something was read successfully into the idi
		 * object, and if not, just continue with a bit sleeping
		 */
		if (result == IDO_ERROR) {
			nanosleep(&delay, NULL);
			continue;
		}

		/*
		 * now handle the newly gotten buffered idi
		 */
		ido2db_handle_input_data(&dbqueue_idi[idi_thread_id]);

                /* sleep a bit */
                nanosleep(&delay, NULL);

                /* should we shutdown? */
                pthread_testcancel();
        }

	/* disconnect thread from database */
        ido2db_db_disconnect(&dbqueue_idi[idi_thread_id]);
        ido2db_db_deinit(&dbqueue_idi[idi_thread_id]);

        /* free memory */
        ido2db_free_input_memory(&dbqueue_idi[idi_thread_id]);
        ido2db_free_connection_memory(&dbqueue_idi[idi_thread_id]);

	/* free idi object */
	//my_free(dbqueue_idi[thread_id]);

        pthread_cleanup_pop(0);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_handle() end\n");

        pthread_exit((void *) pthread_self());
}

/*
 * will handle all data passed to idi object 
 */
int ido2db_handle_input_data(ido2db_idi *idi) {
	int result = IDO_OK;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_input_data() start\n");
	/* 
	 * all functionality below would have happened in ido2db_end_input_data, 
	 * but we read a newly assigned idi object from dbqueue_buf
	 * allowing us to queue all buffers which we will require in the
	 * further data processing
	 */

	/* update db stats occassionally */
	if (ido2db_db_last_checkin_time < (time(NULL) - 60))
		ido2db_db_checkin(idi);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_input_data() input_data: %d\n", idi->current_input_data);

#ifdef DEBUG_IDO2DB2
	printf("HANDLING TYPE: %d\n", idi->current_input_data);
#endif

	switch (idi->current_input_data) {

		/* archived log entries */
	case IDO2DB_INPUT_DATA_LOGENTRY:
		result = ido2db_handle_logentry(idi);
		break;

		/* realtime Icinga data */
	case IDO2DB_INPUT_DATA_PROCESSDATA:
		result = ido2db_handle_processdata(idi);
		break;
	case IDO2DB_INPUT_DATA_TIMEDEVENTDATA:
		result = ido2db_handle_timedeventdata(idi);
		break;
	case IDO2DB_INPUT_DATA_LOGDATA:
		result = ido2db_handle_logdata(idi);
		break;
	case IDO2DB_INPUT_DATA_SYSTEMCOMMANDDATA:
		result = ido2db_handle_systemcommanddata(idi);
		break;
	case IDO2DB_INPUT_DATA_EVENTHANDLERDATA:
		result = ido2db_handle_eventhandlerdata(idi);
		break;
	case IDO2DB_INPUT_DATA_NOTIFICATIONDATA:
		result = ido2db_handle_notificationdata(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICECHECKDATA:
		result = ido2db_handle_servicecheckdata(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTCHECKDATA:
		result = ido2db_handle_hostcheckdata(idi);
		break;
	case IDO2DB_INPUT_DATA_COMMENTDATA:
		result = ido2db_handle_commentdata(idi);
		break;
	case IDO2DB_INPUT_DATA_DOWNTIMEDATA:
		result = ido2db_handle_downtimedata(idi);
		break;
	case IDO2DB_INPUT_DATA_FLAPPINGDATA:
		result = ido2db_handle_flappingdata(idi);
		break;
	case IDO2DB_INPUT_DATA_PROGRAMSTATUSDATA:
		result = ido2db_handle_programstatusdata(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTSTATUSDATA:
		result = ido2db_handle_hoststatusdata(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICESTATUSDATA:
		result = ido2db_handle_servicestatusdata(idi);
		break;
	case IDO2DB_INPUT_DATA_CONTACTSTATUSDATA:
		result = ido2db_handle_contactstatusdata(idi);
		break;
	case IDO2DB_INPUT_DATA_ADAPTIVEPROGRAMDATA:
		result = ido2db_handle_adaptiveprogramdata(idi);
		break;
	case IDO2DB_INPUT_DATA_ADAPTIVEHOSTDATA:
		result = ido2db_handle_adaptivehostdata(idi);
		break;
	case IDO2DB_INPUT_DATA_ADAPTIVESERVICEDATA:
		result = ido2db_handle_adaptiveservicedata(idi);
		break;
	case IDO2DB_INPUT_DATA_ADAPTIVECONTACTDATA:
		result = ido2db_handle_adaptivecontactdata(idi);
		break;
	case IDO2DB_INPUT_DATA_EXTERNALCOMMANDDATA:
		result = ido2db_handle_externalcommanddata(idi);
		break;
	case IDO2DB_INPUT_DATA_AGGREGATEDSTATUSDATA:
		result = ido2db_handle_aggregatedstatusdata(idi);
		break;
	case IDO2DB_INPUT_DATA_RETENTIONDATA:
		result = ido2db_handle_retentiondata(idi);
		break;
	case IDO2DB_INPUT_DATA_CONTACTNOTIFICATIONDATA:
		result = ido2db_handle_contactnotificationdata(idi);
		break;
	case IDO2DB_INPUT_DATA_CONTACTNOTIFICATIONMETHODDATA:
		result = ido2db_handle_contactnotificationmethoddata(idi);
		break;
	case IDO2DB_INPUT_DATA_ACKNOWLEDGEMENTDATA:
		result = ido2db_handle_acknowledgementdata(idi);
		break;
	case IDO2DB_INPUT_DATA_STATECHANGEDATA:
		result = ido2db_handle_statechangedata(idi);
		break;

		/* config file and variable dumps */
	case IDO2DB_INPUT_DATA_MAINCONFIGFILEVARIABLES:
		result = ido2db_handle_configfilevariables(idi, 0);
		break;
	case IDO2DB_INPUT_DATA_RESOURCECONFIGFILEVARIABLES:
		result = ido2db_handle_configfilevariables(idi, 1);
		break;
	case IDO2DB_INPUT_DATA_CONFIGVARIABLES:
		result = ido2db_handle_configvariables(idi);
		break;
	case IDO2DB_INPUT_DATA_RUNTIMEVARIABLES:
		result = ido2db_handle_runtimevariables(idi);
		break;
	case IDO2DB_INPUT_DATA_CONFIGDUMPSTART:
		result = ido2db_handle_configdumpstart(idi);
		break;
	case IDO2DB_INPUT_DATA_CONFIGDUMPEND:
		result = ido2db_handle_configdumpend(idi);
		break;

		/* config definitions */
	case IDO2DB_INPUT_DATA_HOSTDEFINITION:
		result = ido2db_handle_hostdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTGROUPDEFINITION:
		result = ido2db_handle_hostgroupdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICEDEFINITION:
		result = ido2db_handle_servicedefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICEGROUPDEFINITION:
		result = ido2db_handle_servicegroupdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTDEPENDENCYDEFINITION:
		result = ido2db_handle_hostdependencydefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICEDEPENDENCYDEFINITION:
		result = ido2db_handle_servicedependencydefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTESCALATIONDEFINITION:
		result = ido2db_handle_hostescalationdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_SERVICEESCALATIONDEFINITION:
		result = ido2db_handle_serviceescalationdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_COMMANDDEFINITION:
		result = ido2db_handle_commanddefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_TIMEPERIODDEFINITION:
		result = ido2db_handle_timeperiodefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_CONTACTDEFINITION:
		result = ido2db_handle_contactdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_CONTACTGROUPDEFINITION:
		result = ido2db_handle_contactgroupdefinition(idi);
		break;
	case IDO2DB_INPUT_DATA_HOSTEXTINFODEFINITION:
		/* deprecated - merged with host definitions */
		break;
	case IDO2DB_INPUT_DATA_SERVICEEXTINFODEFINITION:
		/* deprecated - merged with service definitions */
		break;

	default:
		break;
	}

	/* free input memory */
	ido2db_free_input_memory(idi);

	/* adjust items processed */
	idi->entries_processed++;

	/*
	 * perform periodic maintenance...
	 * this is done outbound in cleanup thread
	 */
	//ido2db_db_perform_maintenance(idi);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_handle_input_data() end\n");
	return result;
}


/* free memory allocated to data input */
int ido2db_free_input_memory(ido2db_idi *idi) {
	//register int x = 0;
	//register int y = 0;
	int x = 0;
	int y = 0;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_input_memory() start\n");

	if (idi == NULL)
		return IDO_ERROR;

	/* free memory allocated to single-instance data buffers */
	if (idi->buffered_input) {

		for (x = 0; x < IDO_MAX_DATA_TYPES; x++) {
			if (idi->buffered_input[x])
				free(idi->buffered_input[x]);
			idi->buffered_input[x] = NULL;
		}

		free(idi->buffered_input);
		idi->buffered_input = NULL;
	}

	/* free memory allocated to multi-instance data buffers */
	if (idi->mbuf) {
		for (x = 0; x < IDO2DB_MAX_MBUF_ITEMS; x++) {
			if (idi->mbuf[x].buffer) {
				for (y = 0; y < idi->mbuf[x].used_lines; y++) {
					if (idi->mbuf[x].buffer[y]) {
						ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_input_memory() %d|%d used: %d item %s\n", x, y, idi->mbuf[x].used_lines, idi->mbuf[x].buffer[y]);
						free(idi->mbuf[x].buffer[y]);
						idi->mbuf[x].buffer[y] = NULL;
					}
				}
				free(idi->mbuf[x].buffer);
				idi->mbuf[x].buffer = NULL;
			}
			idi->mbuf[x].used_lines = 0;
			idi->mbuf[x].allocated_lines = 0;
		}
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_input_memory() end\n");
	return IDO_OK;
}


/* free memory allocated to connection */
int ido2db_free_connection_memory(ido2db_idi *idi) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_connection_memory() start\n");

	if (idi->instance_name) {
		free(idi->instance_name);
		idi->instance_name = NULL;
	}
	if (idi->agent_name) {
		free(idi->agent_name);
		idi->agent_name = NULL;
	}
	if (idi->agent_version) {
		free(idi->agent_version);
		idi->agent_version = NULL;
	}
	if (idi->disposition) {
		free(idi->disposition);
		idi->disposition = NULL;
	}
	if (idi->connect_source) {
		free(idi->connect_source);
		idi->connect_source = NULL;
	}
	if (idi->connect_type) {
		free(idi->connect_type);
		idi->connect_type = NULL;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_free_connection_memory() end\n");
	return IDO_OK;
}



/****************************************************************************/
/* DATA TYPE CONVERTION ROUTINES                                            */
/****************************************************************************/

int ido2db_convert_standard_data_elements(ido2db_idi *idi, int *type, int *flags, int *attr, struct timeval *tstamp) {
	int result1 = IDO_OK;
	int result2 = IDO_OK;
	int result3 = IDO_OK;
	int result4 = IDO_OK;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_standard_data_elements() start\n");

	result1 = ido2db_convert_string_to_int(idi->buffered_input[IDO_DATA_TYPE], type);
	result2 = ido2db_convert_string_to_int(idi->buffered_input[IDO_DATA_FLAGS], flags);
	result3 = ido2db_convert_string_to_int(idi->buffered_input[IDO_DATA_ATTRIBUTES], attr);
	result4 = ido2db_convert_string_to_timeval(idi->buffered_input[IDO_DATA_TIMESTAMP], tstamp);

	if (result1 == IDO_ERROR || result2 == IDO_ERROR || result3 == IDO_ERROR || result4 == IDO_ERROR)
		return IDO_ERROR;


	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_standard_data_elements() end\n");
	return IDO_OK;
}


int ido2db_convert_string_to_int(char *buf, int *i) {

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_int(%s) start\n", buf);

	*i = atoi(buf);

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_int(%d) end\n", *i);
	return IDO_OK;
}


int ido2db_convert_string_to_float(char *buf, float *f) {
	char *endptr = NULL;

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_float(%s) start\n", buf);

#ifdef HAVE_STRTOF
	*f = strtof(buf, &endptr);
#else
	/* Solaris 8 doesn't have strtof() */
	*f = (float)strtod(buf, &endptr);
#endif

	if (*f == 0 && (endptr == buf || errno == ERANGE))
		return IDO_ERROR;
	if (errno == ERANGE)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_float(%f) end\n", *f);
	return IDO_OK;
}


int ido2db_convert_string_to_double(char *buf, double *d) {
	char *endptr = NULL;

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_double(%s) start\n", buf);

	*d = strtod(buf, &endptr);

	if (*d == 0 && (endptr == buf || errno == ERANGE))
		return IDO_ERROR;
	if (errno == ERANGE)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_double(%lf) end\n", *d);
	return IDO_OK;
}


int ido2db_convert_string_to_long(char *buf, long *l) {
	char *endptr = NULL;

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_long(%s) start\n", buf);

	*l = strtol(buf, &endptr, 0);

	if (*l == LONG_MAX && errno == ERANGE)
		return IDO_ERROR;
	if (*l == 0L && endptr == buf)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_long(%l) end\n", *l);
	return IDO_OK;
}


int ido2db_convert_string_to_unsignedlong(char *buf, unsigned long *ul) {
	char *endptr = NULL;

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_unsignedlong(%s) start\n", buf);

	*ul = strtoul(buf, &endptr, 0);
	if (*ul == ULONG_MAX && errno == ERANGE)
		return IDO_ERROR;
	if (*ul == 0L && endptr == buf)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_unsignedlong(%lu) end\n", *ul);
	return IDO_OK;
}


int ido2db_convert_string_to_timeval(char *buf, struct timeval *tv) {
	char *newbuf = NULL;
	char *ptr = NULL;
	int result = IDO_OK;

	if (buf == NULL)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_timeval(%s) start\n", buf);

	tv->tv_sec = (time_t)0L;
	tv->tv_usec = (suseconds_t)0L;

	if ((newbuf = strdup(buf)) == NULL)
		return IDO_ERROR;

	ptr = strtok(newbuf, ".");
	if ((result = ido2db_convert_string_to_unsignedlong(ptr, (unsigned long *)&tv->tv_sec)) == IDO_OK) {
		ptr = strtok(NULL, "\n");
		result = ido2db_convert_string_to_unsignedlong(ptr, (unsigned long *)&tv->tv_usec);
	}

	free(newbuf);

	if (result == IDO_ERROR)
		return IDO_ERROR;

	//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_convert_string_to_timeval() end\n");
	return IDO_OK;
}



/****************************************************************************/
/* LOGGING ROUTINES                                                         */
/****************************************************************************/

/* opens the debug log for writing */
int ido2db_open_debug_log(void) {

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_open_debug_log() start\n");

	/* don't do anything if we're not debugging */
	if (ido2db_debug_level == IDO2DB_DEBUGL_NONE)
		return IDO_OK;

	if ((ido2db_debug_file_fp = fopen(ido2db_debug_file, "a+")) == NULL) {
		syslog(LOG_ERR, "Warning: Could not open debug file '%s' - '%s'", ido2db_debug_file, strerror(errno));
		return IDO_ERROR;
	}

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_open_debug_log() end\n");

	return IDO_OK;
}


/* closes the debug log */
int ido2db_close_debug_log(void) {

	if (ido2db_debug_file_fp != NULL)
		fclose(ido2db_debug_file_fp);

	ido2db_debug_file_fp = NULL;

	return IDO_OK;
}


/* write to the debug log */
int ido2db_log_debug_info(int level, int verbosity, const char *fmt, ...) {
	va_list ap;
	char *temp_path = NULL;
	time_t t;
	struct tm *tm;
	char temp_time[80];
	struct timeval current_time;

	if (!(ido2db_debug_level == IDO2DB_DEBUGL_ALL || (level & ido2db_debug_level)))
		return IDO_OK;

	if (verbosity > ido2db_debug_verbosity)
		return IDO_OK;

	if (ido2db_debug_file_fp == NULL)
		return IDO_ERROR;

	pthread_mutex_lock(&log_lock);

	/* write the timestamp */
	gettimeofday(&current_time, NULL);

	time(&t);
	tm=localtime(&t);
	strftime(temp_time, 80, "%c", tm);

	fprintf(ido2db_debug_file_fp, "%s .%06lu [%03d.%d] [pid=%lu] [tid=%llu] ", temp_time, current_time.tv_usec, level, verbosity, (unsigned long)getpid(), (unsigned long int)pthread_self());
	//fprintf(ido2db_debug_file_fp, "[%lu.%06lu] [%03d.%d] [pid=%lu] [tid=%llu] ", current_time.tv_sec, current_time.tv_usec, level, verbosity, (unsigned long)getpid(), (unsigned long int)pthread_self());

	/* write the data */
	va_start(ap, fmt);
	vfprintf(ido2db_debug_file_fp, fmt, ap);
	va_end(ap);

	/* flush, so we don't have problems tailing or when fork()ing */
	fflush(ido2db_debug_file_fp);

	pthread_mutex_unlock(&log_lock);

	/* if file has grown beyond max, rotate it */
	if ((unsigned long)ftell(ido2db_debug_file_fp) > ido2db_max_debug_file_size && ido2db_max_debug_file_size > 0L) {

		/* close the file */
		ido2db_close_debug_log();

		/* rotate the log file */
		if (asprintf(&temp_path, "%s.old", ido2db_debug_file) == -1)
			temp_path = NULL;

		if (temp_path) {

			/* unlink the old debug file */
			unlink(temp_path);

			/* rotate the debug file */
			my_rename(ido2db_debug_file, temp_path);

			/* free memory */
			my_free(temp_path);
		}

		/* open a new file */
		ido2db_open_debug_log();
	}

	return IDO_OK;
}


/********************************************************************
 *
 * working on dbuf - this is the function for the buffer reading thread
 *
 ********************************************************************/

void * ido2db_thread_worker(void *data) {

	ido2db_idi *idi = (ido2db_idi*) data;

	struct timespec delay;
	delay.tv_sec = 5;
	delay.tv_nsec = 500000;
	nanosleep(&delay, NULL);
	delay.tv_sec = 0;

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_worker() start\n");

	/* specify cleanup routine */
	pthread_cleanup_push((void *) &ido2db_thread_worker_exit_handler, NULL);

	/* set cancellation info */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	while (1) {

		/* should we shutdown? */
		pthread_testcancel();

		/* sleep a bit */
		nanosleep(&delay, NULL);

		if (idi->disconnect_client == IDO_TRUE) {
			ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_worker(): origin idi said we should disconnect the client\n");
			break;
		}

		/* check for client input */
		//ido2db_check_for_client_input(idi);

		/* sleep a bit */
		nanosleep(&delay, NULL);

		/* should we shutdown? */
		pthread_testcancel();
	}

	pthread_cleanup_pop(0);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_worker() end\n");

	pthread_exit((void *) pthread_self());
}


/* ******************************************************************
 *
 * exit_handler_mem is called as thread canceling
 *
 * ******************************************************************/

static void *ido2db_thread_worker_exit_handler(void * arg) {
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_worker() cleanup_exit_handler...\n");
	return 0;

}

static void *ido2db_thread_dbqueue_exit_handler(void * arg) {
        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_dbqueue_exit_handler () cleanup thread_id %d\n", pthread_self());
        return 0;

}


/********************************************************************
 *
 * housekeeping - this is the function for the db trimming thread
 *
 ********************************************************************/

void * ido2db_thread_cleanup(void *data) {

	ido2db_idi *idi = (ido2db_idi*) data;

	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = 500;

	/* it might happen that db connection comes to fast after main thread so sleep a while */
	//delay.tv_sec = 60;
	/* allowed to be set in config */
	delay.tv_sec = ido2db_db_settings.housekeeping_thread_startup_delay;

	/* the minimum is the default, otherwise overwrite */
	if (delay.tv_sec < DEFAULT_HOUSEKEEPING_THREAD_STARTUP_DELAY)
		delay.tv_sec = DEFAULT_HOUSEKEEPING_THREAD_STARTUP_DELAY;

	nanosleep(&delay, NULL);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() start\n");

	/* initialize input data information */
	ido2db_idi_init(&thread_idi);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() initialize thread db connection\n");

	/* initialize database connection */
	ido2db_db_init(&thread_idi);

	if (ido2db_db_connect(&thread_idi) == IDO_ERROR) {

		/* tell main process to disconnect */
		idi->disconnect_client = IDO_TRUE;

		/* cleanup the thread */
		ido2db_db_deinit(&thread_idi);

		/* free memory */
		ido2db_free_input_memory(&thread_idi);
		ido2db_free_connection_memory(&thread_idi);

		return (void*)IDO_ERROR;
	}

	/* specify cleanup routine */
	pthread_cleanup_push((void *) &ido2db_thread_cleanup_exit_handler, NULL);

	delay.tv_sec = 0;
	delay.tv_nsec = 500;

	/* keep on looping for an instance name from main thread */
	while (idi->instance_name == NULL) {
		//ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() nanosleeping cause missing instance_name...\n");
		nanosleep(&delay, NULL);
	}


	/* copy needed idi information */
	thread_idi.instance_name = idi->instance_name;
	thread_idi.agent_name = "IDO2DB Trimming Thread";
	thread_idi.agent_version = idi->agent_version;
	thread_idi.disposition = idi->disposition;
	thread_idi.connect_source = idi->connect_source;
	thread_idi.connect_type = idi->connect_type;

	delay.tv_sec = 5;

	/* save connection info to DB */
	while (ido2db_thread_db_hello(&thread_idi) == IDO_ERROR) {
		ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() no instance found, sleeping...\n");
		nanosleep(&delay, NULL);
	}

	while (1) {

		/* should we shutdown? */
		pthread_testcancel();

		if (idi->disconnect_client == IDO_TRUE) {
			ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup(): origin idi said we should disconnect the client\n");
			break;
		}

		/* Perfom DB Maintenance */
		ido2db_db_perform_maintenance(&thread_idi);

		/* should we shutdown? */
		pthread_testcancel();

		sleep(thread_idi.dbinfo.trim_db_interval + 1);
	}

	/* gracefully back out of current operation... */
	ido2db_db_goodbye(&thread_idi);

	/* disconnect from database */
	ido2db_db_disconnect(&thread_idi);
	ido2db_db_deinit(&thread_idi);

	/* free memory */
	ido2db_free_input_memory(&thread_idi);
	ido2db_free_connection_memory(&thread_idi);

	pthread_cleanup_pop(0);

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() end\n");

	pthread_exit((void *) pthread_self());
}

/* ******************************************************************
 *
 * exit_handler_mem is called as thread canceling
 *
 * ******************************************************************/

static void *ido2db_thread_cleanup_exit_handler(void * arg) {
	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_thread_cleanup() cleanup_exit_handler...\n");
	return 0;

}

int ido2db_disconnect_threads(void) {
	int t = 0;

        /* from cleaner thread */
        ido2db_db_disconnect(&thread_idi);
        ido2db_db_deinit(&thread_idi);

        /* TODO deinit idi from dbqueue threads */
        for (t = 0; t < IDO2DB_DBQUEUE_THREADS; t++) {
                ido2db_db_disconnect(&dbqueue_idi[t]);
                ido2db_db_deinit(&dbqueue_idi[t]);
        }

	return IDO_OK;
}

int ido2db_terminate_threads(void) {

	int result;
	result = ido2db_disconnect_threads();

	/* terminate each thread on its own */
	/*result=terminate_worker_thread();*/
	result = terminate_cleanup_thread();
	result = terminate_queue_thread();
	result = terminate_dbqueue_threads();

	return IDO_OK;
}

int terminate_worker_thread(void) {

	int result;

	result = pthread_cancel(thread_pool[IDO2DB_THREAD_POOL_WORKER]);
	/* wait for the worker thread to exit */
	if (result == 0) {
		result = pthread_join(thread_pool[IDO2DB_THREAD_POOL_WORKER], NULL);
	} /* else only clean memory */

	return IDO_OK;

}

int terminate_cleanup_thread(void) {

	int result;

	result = pthread_cancel(thread_pool[IDO2DB_THREAD_POOL_CLEANER]);
	/* wait for the cleaner thread to exit */
	if (result == 0) {
		result = pthread_join(thread_pool[IDO2DB_THREAD_POOL_CLEANER], NULL);
	} /* else only clean memory */

	return IDO_OK;

}

int terminate_queue_thread(void) {

        int result;

        result = pthread_cancel(queue_thread);
        /* wait for the queue thread to exit */
        if (result == 0) {
                result = pthread_join(queue_thread, NULL);
        } /* else only clean memory */

        return IDO_OK;
}

int terminate_dbqueue_threads(void) {
        int result = IDO_OK;
	int t = 0;

	for (t = 0; t < IDO2DB_DBQUEUE_THREADS; t++) {
		if (pthread_join(dbqueue_thread[t], NULL) != 0)
			result = IDO_ERROR;
	}

        return result;
}
