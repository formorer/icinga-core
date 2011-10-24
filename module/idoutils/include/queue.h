/************************************************************************
 *
 * QUEUE.H - IDO2DB QUEUE Include File
 *
 * Copyright (c) 2011 Icinga Development Team (http://www.icinga.org)
 * 
 ************************************************************************/

#ifndef _IDO2DB_QUEUE_H
#define _IDO2DB_QUEUE_H

#include "ido2db.h"

#define IDO2DB_SINK_BUFFER_SLOTS                        500000
#define IDO2DB_SINK_RETRY_ON_ERROR                      5

#define IDO2DB_DBQUEUE_BUF_SLOTS                        50000
#define IDO2DB_DBQUEUE_RETRY_ON_ERROR                   5


typedef struct ido2db_sink_buffer_struct{
        char **buffer;
        unsigned long size;
        unsigned long head;
        unsigned long tail;
        unsigned long items;
        unsigned long maxitems;
        unsigned long overflow;
        pthread_mutex_t buffer_lock;
        }ido2db_sink_buffer;

typedef struct ido2db_dbqueue_item_struct{
	/* we copy that information on thread startup
	 * or from main thread if we need it
	 * instance_name, ignore_client_data
	 */
	/*
        int protocol_version;
        int disconnect_client;
        int ignore_client_data;
        char *instance_name;
        char *agent_name;
        char *agent_version;
        char *disposition;
        char *connect_source;
        char *connect_type;
	*/
	/*
	 * we need to know what we are currntly processing
	 */
        int current_input_section;
        int current_input_data;
        /* ToDo change *_processed  to unsigned long long */
	/* that information is just for the main idi object
	 * not for the worker threads on dbqueue
	 */
	/*
        unsigned long bytes_processed;
        unsigned long lines_processed;
        unsigned long entries_processed;
        unsigned long data_start_time;
        unsigned long data_end_time;
	*/
	/*
	 * we need to know which config_type
	 */
        int current_object_config_type;
	/*
	 * this is the important part, keep the pointers to the buffers
	 */
        char **buffered_input;
        ido2db_mbuf mbuf[IDO2DB_MAX_MBUF_ITEMS];
	/* 
	 * we keep our own db information so don't queue that
	 * dbinfo.instance_id is the important part we need to
	 * inherit from the main process!
	 */
        /* ido2db_dbconninfo dbinfo; */
        }ido2db_dbqueue_item;

typedef struct ido2db_dbqueue_buf_struct{
        ido2db_dbqueue_item **buffer;
        unsigned long size;
        unsigned long head;
        unsigned long tail;
        unsigned long items;
        unsigned long maxitems;
        unsigned long overflow;
        pthread_mutex_t buffer_lock;
        }ido2db_dbqueue_buf;


int ido2db_sink_buffer_init(ido2db_sink_buffer *, unsigned long);
int ido2db_sink_buffer_deinit(ido2db_sink_buffer *);
int ido2db_sink_buffer_push(ido2db_sink_buffer *, char *);
char *ido2db_sink_buffer_peek(ido2db_sink_buffer *);
char *ido2db_sink_buffer_pop(ido2db_sink_buffer *);
int ido2db_sink_buffer_items(ido2db_sink_buffer *);
unsigned long ido2db_sink_buffer_get_overflow(ido2db_sink_buffer *);
int ido2db_sink_buffer_set_overflow(ido2db_sink_buffer *, unsigned long);
int ido2db_load_unprocessed_data(ido2db_sink_buffer *, char *);
int ido2db_save_unprocessed_data(ido2db_sink_buffer *, char *);

int ido2db_dbqueue_buf_init(ido2db_dbqueue_buf *, unsigned long);
int ido2db_dbqueue_buf_deinit(ido2db_dbqueue_buf *);
int ido2db_dbqueue_buf_push(ido2db_dbqueue_buf *, ido2db_idi *);
int ido2db_dbqueue_buf_pop(ido2db_dbqueue_buf *, ido2db_idi *);



#endif
