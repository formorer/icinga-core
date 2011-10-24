/***************************************************************
 * QUEUE.C - Queue and buffer routines for IDO2DB daemon
 *
 * Copyright (c) 2011 Icinga Development Team (http://www.icinga.org)
 *
 **************************************************************/

/* include our project's header files */
#include "../../../include/config.h"
#include "../include/common.h"
#include "../include/io.h"
#include "../include/utils.h"
#include "../include/protoapi.h"
#include "../include/ido2db.h"
#include "../include/queue.h"

/* Icinga header files */
#include "../../../include/icinga.h"
#include "../../../include/broker.h"
#include "../../../include/comments.h"

extern int errno;

extern int ido2db_dbqueue_buf_slots;

/****************************************************************************/
/* DBQUEUE                                                                  */
/****************************************************************************/

/* TODO create new functions for dbqueue buffer */

/* initializes dbqueue buffer */
int ido2db_dbqueue_buf_init(ido2db_dbqueue_buf *dbqueue_buf, unsigned long maxitems) {
        unsigned long x;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_init() start\n");

        if (dbqueue_buf == NULL || maxitems <= 0)
                return IDO_ERROR;

        /* allocate memory for the buffer */
        if ((dbqueue_buf->buffer = (ido2db_dbqueue_item **)malloc(sizeof(ido2db_dbqueue_item *) * maxitems))) {
                for (x = 0; x < maxitems; x++)
                        dbqueue_buf->buffer[x] = NULL;
        }

        dbqueue_buf->size = 0L;
        dbqueue_buf->head = 0L;
        dbqueue_buf->tail = 0L;
        dbqueue_buf->items = 0L;
        dbqueue_buf->maxitems = maxitems;
        dbqueue_buf->overflow = 0L;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_init() end\n");

        return IDO_OK;
}

/* deinitializes dbqueue buffer */
int ido2db_dbqueue_buf_deinit(ido2db_dbqueue_buf *dbqueue_buf) {
        unsigned long x;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_deinit() start\n");

        if (dbqueue_buf == NULL)
                return IDO_ERROR;

	/* free dbqueue_item */
        
	/* free any allocated memory */
        for (x = 0; x < dbqueue_buf->maxitems; x++)
                free(dbqueue_buf->buffer[x]);

        free(dbqueue_buf->buffer);
        dbqueue_buf->buffer = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_deinit() end\n");

        return IDO_OK;
}

/* buffers dbqueue (PUSH) */
int ido2db_dbqueue_buf_push(ido2db_dbqueue_buf *dbqueue_buf, ido2db_idi *idi) {
	int buffer_items, head, tail = 0;
	int x = 0;
	int y = 0;

	/*
	 * we will copy all valid elements from idi buffers
	 * into a new item, but first we need to get a lock
	 * in order to keep data save
	 */
        /* get a lock on the buffer */
        pthread_mutex_lock(&dbqueue_buf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_push() start\n");

	ido2db_dbqueue_item *dbqueue_item = (ido2db_dbqueue_item *)calloc(1, sizeof(ido2db_dbqueue_item));

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_push() dbqueue_buf items: %d/%d head: %d tail: %d\n", dbqueue_buf->items, ido2db_dbqueue_buf_slots, dbqueue_buf->head, dbqueue_buf->tail);

        if (dbqueue_buf == NULL || idi == NULL) {
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }

        /* no space to store buffer */
        if (dbqueue_buf->buffer == NULL || dbqueue_buf->items == dbqueue_buf->maxitems) {
                dbqueue_buf->overflow++;
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }

        /* store dbqueue item */
	/* TODO
	 * different approach here, store the pointers to
	 * buffered_input, and mbuf
	 * then loop through mbuf and copy all members pointers
	 * after that, copy all non pointer values
	 */

        /*
         * current_* values
         */
        dbqueue_item->current_input_section = idi->current_input_section;
        dbqueue_item->current_input_data = idi->current_input_data;
        dbqueue_item->current_object_config_type = idi->current_object_config_type;

        /*
         * buffered_input
	 * reset origin buffer to avoid free'ing in the wrong place
         */
	if (idi->buffered_input) {
	        dbqueue_item->buffered_input = idi->buffered_input;

                for (x = 0; x < IDO_MAX_DATA_TYPES; x++) {
                        if (idi->buffered_input[x]) {
				/*
				 * actually copy the complete char*
				 * free idi after pushing successfully
				 */
				dbqueue_item->buffered_input[x] = strdup(idi->buffered_input[x]);
                                ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_push() buffered_input [%d]: %s\n", x, dbqueue_item->buffered_input[x]);
				//my_free(idi->buffered_input[x]);
			}
                 }

	}

        /*
         * mbuf
         */
	/*
	 * make sure we only copy pointers to regions
	 * data was written to
	 */
	if (idi->mbuf) {
	        for (x = 0; x < IDO2DB_MAX_MBUF_ITEMS; x++) {
			if (idi->mbuf[x].buffer) {		
		                dbqueue_item->mbuf[x].used_lines = idi->mbuf[x].used_lines;
		                dbqueue_item->mbuf[x].allocated_lines = idi->mbuf[x].allocated_lines;
		                dbqueue_item->mbuf[x].buffer = idi->mbuf[x].buffer;
				/*
				 * also copy all buffer lines, not only mbuf slots!
				 */
		                for (y = 0; y < idi->mbuf[x].used_lines; y++) {
					if (idi->mbuf[x].buffer[y]) {
						/*
						 * actually copy the complete char*
						 * free idi after pushing successfully
						 */
			                        dbqueue_item->mbuf[x].buffer[y] = strdup(idi->mbuf[x].buffer[y]);
						ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_push() mbuf %d|%d: %s\n", x, y, dbqueue_item->mbuf[x].buffer[y]);
						//my_free(idi->mbuf[x].buffer[y]);
					}
		                }
			}
        	}
	}


        /*
         * we need to reassign the following information
         * current_input_section
         * current_input_data
         * current_object_config_type
         * *buffered_input
         * mbuf[IDO2DB_MAX_MBUF_ITEMS]
         */
	dbqueue_buf->buffer[dbqueue_buf->head] = dbqueue_item;

	/*
	 * adjust counters
	 */
        dbqueue_buf->head = (dbqueue_buf->head + 1) % dbqueue_buf->maxitems;
        dbqueue_buf->items++;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_push() end\n");

	/*
	 * free the calloc memory
	 */
	//my_free(dbqueue_item);

        /* release the lock on the buffer */
        pthread_mutex_unlock(&dbqueue_buf->buffer_lock);

        return IDO_OK;
}

/* gets and removes next item from buffer */
int ido2db_dbqueue_buf_pop(ido2db_dbqueue_buf *dbqueue_buf, ido2db_idi *idi) {
	int buffer_items, head, tail = 0;
	int x = 0;
	int y = 0;

	/*
	 * we will copy all valid elements from
	 * the dbqueue_item to the provided
	 * idi object, re-assigning all pointers
	 * we do this after acquiring a lock on the
	 * buffer to keep data save
	 */

        /* get a lock on the buffer */
        pthread_mutex_lock(&dbqueue_buf->buffer_lock);

	ido2db_dbqueue_item *dbqueue_item = (ido2db_dbqueue_item *)calloc(1, sizeof(ido2db_dbqueue_item));;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() start\n");

	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() dbqueue_buf items: %d/%d head: %d tail: %d\n", dbqueue_buf->items, ido2db_dbqueue_buf_slots, dbqueue_buf->head, dbqueue_buf->tail);

        if (dbqueue_buf == NULL || idi == NULL) {
        	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() dbqueue_buf, idi NULL\n");
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }

        if (dbqueue_buf->buffer == NULL) {
        	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() buffer NULL\n");
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }

	/*
	 * buffer empty, so bail out
	 */
        if (dbqueue_buf->items == 0) {
        	ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() no items\n");
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }

        /* remove item from buffer */

	/*
	 * we need to reassign the following information
	 * current_input_section
	 * current_input_data
	 * current_object_config_type
	 * *buffered_input
	 * mbuf[IDO2DB_MAX_MBUF_ITEMS]
	 */

        dbqueue_item = dbqueue_buf->buffer[dbqueue_buf->tail];

	/*
	 * XXX check if dbqueue_item is NULL?
	 */
	if (dbqueue_item == NULL) {
	        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() dbqueue_item NULL\n");
                pthread_mutex_unlock(&dbqueue_buf->buffer_lock);
                return IDO_ERROR;
        }
	

	/*
	 * current_* values
	 */
	idi->current_input_section = dbqueue_item->current_input_section;
	idi->current_input_data = dbqueue_item->current_input_data;
	idi->current_object_config_type = dbqueue_item->current_object_config_type;

	/*
	 * buffered_input
	 */
	if (dbqueue_item->buffered_input) {
		idi->buffered_input = dbqueue_item->buffered_input;

	        for (x = 0; x < IDO_MAX_DATA_TYPES; x++) {
	                if (dbqueue_item->buffered_input[x]) {
				idi->buffered_input[x] = strdup(dbqueue_item->buffered_input[x]);
				ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() buffered_input [%d]: %s\n", x, idi->buffered_input[x]);		
				//my_free(dbqueue_item->buffered_input[x]);
			}
	         }
	}


	/*
	 * mbuf
	 */
	/*
	 * make sure to read pointers only from
	 * locations actually written before
	 */
	if (dbqueue_item->mbuf) {
	        for (x = 0; x < IDO2DB_MAX_MBUF_ITEMS; x++) {
			if (dbqueue_item->mbuf[x].buffer) {
		                idi->mbuf[x].used_lines =  dbqueue_item->mbuf[x].used_lines;
		                idi->mbuf[x].allocated_lines =  dbqueue_item->mbuf[x].allocated_lines;
		                idi->mbuf[x].buffer = dbqueue_item->mbuf[x].buffer;
				/*
				 * also copy all buffer lines, not only mbuf slots!
				 */
				for (y = 0; y < idi->mbuf[x].used_lines; y++) {
					if(dbqueue_item->mbuf[x].buffer[y]) {
						idi->mbuf[x].buffer[y] = strdup(dbqueue_item->mbuf[x].buffer[y]);
						ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() mbuf %d|%d: %s\n", x, y, idi->mbuf[x].buffer[y]);
						//my_free(dbqueue_item->mbuf[x].buffer[y]);
					}
				}
			}
	        }
	}

	/*
	 * remove item from the buffer, resetting pointers
	 */
	//free(dbqueue_buf->buffer[dbqueue_buf->tail]);
	dbqueue_buf->buffer[dbqueue_buf->tail] = NULL;

        dbqueue_buf->tail = (dbqueue_buf->tail + 1) % dbqueue_buf->maxitems;
        dbqueue_buf->items--;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_dbqueue_buf_pop() end\n");

	/* do not free any buffer memory right now
	 * this must be taken care of after having
	 * processed the idi object buffers
	 */
	my_free(dbqueue_item);
	
        /* release the lock on the buffer */
        pthread_mutex_unlock(&dbqueue_buf->buffer_lock);

        return IDO_OK;
}


/****************************************************************************/
/* SINKBUFFERFUNCTIONS                                                      */
/****************************************************************************/


/* initializes sink buffer */
int ido2db_sink_buffer_init(ido2db_sink_buffer *sbuf, unsigned long maxitems) {
        unsigned long x;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_init() start\n");

        if (sbuf == NULL || maxitems <= 0)
                return IDO_ERROR;

        /* allocate memory for the buffer */
        if ((sbuf->buffer = (char **)malloc(sizeof(char *) * maxitems))) {
                for (x = 0; x < maxitems; x++)
                        sbuf->buffer[x] = NULL;
        }

        sbuf->size = 0L;
        sbuf->head = 0L;
        sbuf->tail = 0L;
        sbuf->items = 0L;
        sbuf->maxitems = maxitems;
        sbuf->overflow = 0L;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_init() end\n");

        return IDO_OK;
}

/* deinitializes sink buffer */
int ido2db_sink_buffer_deinit(ido2db_sink_buffer *sbuf) {
        unsigned long x;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_deinit() start\n");

        if (sbuf == NULL)
                return IDO_ERROR;

        /* free any allocated memory */
        for (x = 0; x < sbuf->maxitems; x++)
                free(sbuf->buffer[x]);

        free(sbuf->buffer);
        sbuf->buffer = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_deinit() end\n");

        return IDO_OK;
}

/* buffers output */
int ido2db_sink_buffer_push(ido2db_sink_buffer *sbuf, char *buf) {

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_push() start\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL || buf == NULL) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return IDO_ERROR;
        }

        /* no space to store buffer */
        if (sbuf->buffer == NULL || sbuf->items == sbuf->maxitems) {
                sbuf->overflow++;
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return IDO_ERROR;
        }

        /* store buffer */
        sbuf->buffer[sbuf->head] = strdup(buf);
        sbuf->head = (sbuf->head + 1) % sbuf->maxitems;
        sbuf->items++;

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_push() end\n");

        return IDO_OK;
}

/* gets and removes next item from buffer */
char *ido2db_sink_buffer_pop(ido2db_sink_buffer *sbuf) {
        char *buf = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_pop() start\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return NULL;
        }

        if (sbuf->buffer == NULL) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return NULL;
        }

        if (sbuf->items == 0) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return NULL;
        }

        /* remove item from buffer */
        buf = sbuf->buffer[sbuf->tail];
        sbuf->buffer[sbuf->tail] = NULL;
        sbuf->tail = (sbuf->tail + 1) % sbuf->maxitems;
        sbuf->items--;

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_pop() end\n");

        return buf;
}

/* gets next items from buffer */
char *ido2db_sink_buffer_peek(ido2db_sink_buffer *sbuf) {
        char *buf = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_peek() start\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return NULL;
        }

        if (sbuf->buffer == NULL) {
                pthread_mutex_unlock(&sbuf->buffer_lock);
                return NULL;
        }

        buf = sbuf->buffer[sbuf->tail];

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_peek() end\n");

        return buf;
}

/* returns number of items buffered */
int ido2db_sink_buffer_items(ido2db_sink_buffer *sbuf) {
        int items = 0;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_items()\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL)
                items = 0;
        else
                items = sbuf->items;

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_items() items: %d\n", items);

        return items;
}

/* gets number of items lost due to buffer overflow */
unsigned long ido2db_sink_buffer_get_overflow(ido2db_sink_buffer *sbuf) {
        int overflow = 0;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_get_overflow()\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL)
                overflow = 0;
        else
                overflow = sbuf->overflow;

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_get_overflow() overflow: %d\n", overflow);

        return overflow;
}

/* sets number of items lost due to buffer overflow */
int ido2db_sink_buffer_set_overflow(ido2db_sink_buffer *sbuf, unsigned long num) {
        int overflow = 0;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_set_overflow()\n");

        /* get a lock on the buffer */
        pthread_mutex_lock(&sbuf->buffer_lock);

        if (sbuf == NULL) {
                overflow = 0;
        } else {
                sbuf->overflow = num;
                overflow = num;
        }

        /* release the lock on the buffer */
        pthread_mutex_unlock(&sbuf->buffer_lock);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_sink_buffer_set_overflow() overflow: %d\n", overflow);

        return overflow;
}
/* save unprocessed data to buffer file */
int ido2db_save_unprocessed_data(ido2db_sink_buffer *sbuf, char *f) {
        FILE *fp = NULL;
        char *buf = NULL;
        char *ebuf = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_save_unprocessed_data() start\n");

        /* no file */
        if (f == NULL)
                return IDO_OK;

        /* open the file for writing */
        if ((fp = fopen(f, "w")) == NULL)
                return IDO_ERROR;

        /* save all buffered items */
        while (ido2db_sink_buffer_items(sbuf) > 0) {

                /* get next item from buffer */
                buf = ido2db_sink_buffer_pop(sbuf);

                /* escape the string */
                ebuf = ido_escape_buffer(buf);

                /* write string to file */
                fputs(ebuf, fp);
                fputs("\n", fp);

                /* free memory */
                free(buf);
                buf = NULL;
                free(ebuf);
                ebuf = NULL;
        }

        fclose(fp);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_save_unprocessed_data() end\n");

        return IDO_OK;
}

/* load unprocessed data from buffer file */
int ido2db_load_unprocessed_data(ido2db_sink_buffer *sbuf, char *f) {
        ido_mmapfile *thefile = NULL;
        char *ebuf = NULL;
        char *buf = NULL;

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_load_unprocessed_data() start\n");

        /* open the file */
        if ((thefile = ido_mmap_fopen(f)) == NULL)
                return IDO_ERROR;

        /* process each line of the file */
        while ((ebuf = ido_mmap_fgets(thefile))) {

                /* unescape string */
                buf = ido_unescape_buffer(ebuf);

                /* save the data to the sink buffer */
                ido2db_sink_buffer_push(sbuf, buf);

                /* free memory */
                free(ebuf);
        }

        /* close the file */
        ido_mmap_fclose(thefile);

        /* remove the file so we don't process it again in the future */
        unlink(f);

        ido2db_log_debug_info(IDO2DB_DEBUGL_PROCESSINFO, 2, "ido2db_load_unprocessed_data() end\n");

        return IDO_OK;
}

