/************************************************************************
 *
 * SLA.H - SLA functions
 * Copyright (c) 2011 Icinga Development Team (http://www.icinga.org)
 *
 ************************************************************************/


#ifndef _SLA_H
#define	_SLA_H

#include "ido2db.h"
/*
 * A single entry in the SLA state history.
 */
typedef struct sla_state_s {
    int persistent;
    unsigned long slahistory_id;
    unsigned long instance_id;
    time_t start_time;
    time_t end_time;
    time_t acknowledgement_time;
    unsigned long object_id;
    int state;
    int state_type;
    int scheduled_downtime;
} sla_state_t;

/*
 * A list of multiple SLA state history entries.
 */

typedef struct sla_state_list_s {
    unsigned int count;
    sla_state_t states[0];
} sla_state_list_t;

/**
 * A downtime entry.
 */
typedef struct sla_downtime_s {
    unsigned long downtimehistory_id;
    unsigned long instance_id;
    unsigned long object_id;
    int is_fixed;
    int duration;
    time_t scheduled_start_time;
    time_t scheduled_end_time;
    time_t actual_start_time;
    time_t actual_end_time;
} sla_downtime_t;

/**
 * A list of multiple downtime entries.
 */
typedef struct sla_downtime_list_s {
    unsigned int count;
    sla_downtime_t downtimes[0];
} sla_downtime_list_t;

sla_state_t *sla_alloc_state(unsigned long, unsigned long);
void sla_free_state(sla_state_t *);

sla_state_list_t *sla_realloc_state_list(sla_state_list_t *, unsigned int);
sla_state_list_t *sla_alloc_state_list(unsigned int);
void sla_free_state_list(sla_state_list_t *);

int sla_query_states(ido2db_idi *, unsigned long, time_t, time_t, sla_state_list_t **);
int sla_save_state(ido2db_idi *, sla_state_t *);
int sla_delete_state(ido2db_idi *, sla_state_t *);

sla_downtime_t *sla_alloc_downtime(unsigned long, unsigned long);
void sla_free_downtime(sla_downtime_t *);

sla_downtime_list_t *sla_alloc_downtime_list(unsigned int);
void sla_free_downtime_list(sla_downtime_list_t *);

int sla_query_downtime(ido2db_idi *, unsigned long, time_t, time_t, sla_downtime_list_t **);
int sla_apply_downtime(ido2db_idi *, sla_state_list_t **, sla_downtime_list_t *);

int sla_process_statechange(ido2db_idi *, unsigned long, time_t, time_t, const int *, const int *, const int *);
int sla_process_acknowledgement(ido2db_idi *, unsigned long, time_t, int);
int sla_process_downtime(ido2db_idi *, unsigned long, time_t, int);
int sla_process_downtime_history(ido2db_idi *, unsigned long, time_t, time_t);

#endif	/* _SLA_H */
