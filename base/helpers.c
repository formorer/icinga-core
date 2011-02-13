/*****************************************************************************
 *
 * HELPERS.C - Core Program Code refactored from Icinga
 *
 * Program: Icinga
 * Version: 1.3.0
 * License: GPL
 * Copyright (c) 2010 James Michael DuPont
 * Copyright (c) 2009-2011 Icinga Development Team (http://www.icinga.org)
 *
 * Description:
 *
 * These helper functions are refactored from the icinga code to isolate unsafe type operations into a central place
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *****************************************************************************/

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/comments.h"
#include "../include/downtime.h"
#include "../include/statusdata.h"
#include "../include/macros.h"
#include "../include/icinga.h"
#include "../include/sretention.h"
#include "../include/perfdata.h"
#include "../include/broker.h"
#include "../include/nebmods.h"
#include "../include/nebmodules.h"
#include <assert.h>

/* make sure gcc3 won't hit here */
#ifndef GCCTOOOLD
#include "../include/profiler.h"
#endif

/*#define DEBUG_MEMORY 1*/
#ifdef DEBUG_MEMORY
#include <mcheck.h>
#endif

int assign_mod_initfunc_ptr(nebmodule * pmodule,module_func_ptr_t pfunc)
{
  if (sizeof (pmodule->init_func) ==sizeof(pfunc))
    {
      pmodule->init_func = (mod_initfunc_ptr_t)pfunc;
      return 0;
    }
  else
    {
      assert(0);
    }
  return -1;
}

int assign_mod_deinitfunc_ptr(nebmodule *pmodule,module_func_ptr_t pfunc)
{
  if (sizeof (pmodule->init_func) ==sizeof(pfunc))
    {
        pmodule->deinit_func= (mod_deinitfunc_ptr_t)pfunc;
	return 0;
    }
  else
    {
      assert(0);
    }
  return -1;
}


void free_event(int event_type,event_data_obj_t event_data)
{
  free(event_data.anything);
}
 
unsigned long * get_event_unsigned_long_ptr(event_data_obj_t data)
{
  return data.unsigned_long_ptr; // do we really need this?
}
unsigned long get_event_unsigned_long(event_data_obj_t data)
{
  return data.unsigned_long;
}

service_ptr_t get_event_service(event_data_obj_t data)
{
  return data.service;
}
host_ptr_t get_event_host(event_data_obj_t data)
{
  return data.host;
}


event_data_obj_t get_event_null(void)
{
  event_data_obj_t argobj;
  argobj.anything =0;
  return argobj;
}

event_args_ptr_t get_event_args_null(void)
{
  event_args_ptr_t ret=0;
  return ret;

}



int schedule_new_event_basic(
int event_type, int high_priority, time_t run_time, int recurring, unsigned long event_interval, time_function_ptr_t timing_func, int compensate_for_time_change)	/* schedules a new timed event */
{
  event_data_obj_t argobj;
  argobj.anything =0;
  return schedule_new_event(event_type, 
			    high_priority, 
			    run_time, 
			    recurring, 
			    event_interval, 
			    timing_func, 
			    compensate_for_time_change, 
			    argobj,
			    0,
			    0);
}

int schedule_new_service_event(
int event_type, int high_priority, time_t run_time, int recurring, unsigned long event_interval, time_function_ptr_t timing_func, int compensate_for_time_change,service_ptr_t event_data,event_args_ptr_t event_args,int event_options)	/* schedules a new timed event */
{
  event_data_obj_t argobj;
  argobj.service =event_data;
  return schedule_new_event(event_type, 
			    high_priority, 
			    run_time, 
			    recurring, 
			    event_interval, 
			    timing_func, 
			    compensate_for_time_change, 
			    argobj,
			    event_args,
			    event_options);
}

int schedule_new_host_event(int event_type, int high_priority, time_t run_time, int recurring, unsigned long event_interval, time_function_ptr_t timing_func, int compensate_for_time_change,host_ptr_t event_data,event_args_ptr_t event_args,int event_options)	/* schedules a new timed event */
{
  event_data_obj_t argobj;
  argobj.host =event_data;
  return schedule_new_event(event_type, 
			    high_priority, 
			    run_time, 
			    recurring, 
			    event_interval, 
			    timing_func, 
			    compensate_for_time_change, 
			    argobj,
			    event_args,
			    event_options);
}


int schedule_new_event_unsigned_long_ptr(int event_type, int high_priority, time_t run_time, int recurring, unsigned long event_interval, time_function_ptr_t timing_func, int compensate_for_time_change, unsigned long * args)	/* schedules a new timed event */
{
  event_data_obj_t argobj;
  argobj.unsigned_long_ptr =args;
  return schedule_new_event(event_type, 
			    high_priority, 
			    run_time, 
			    recurring, 
			    event_interval, 
			    timing_func, 
			    compensate_for_time_change, 
			    argobj,0,0);
}


int schedule_new_event_unsigned_long(int event_type, int high_priority, time_t run_time, int recurring, unsigned long event_interval, time_function_ptr_t timing_func, int compensate_for_time_change, unsigned long  args)	/* schedules a new timed event */
{
  event_data_obj_t argobj;
  argobj.unsigned_long =args;
  return schedule_new_event(event_type, 
			    high_priority, 
			    run_time, 
			    recurring, 
			    event_interval, 
			    timing_func, 
			    compensate_for_time_change, 
			    argobj,0,0);
}


/*
int cleanup_downtime_data(char *)
{}

int handle_scheduled_downtime_by_id(unsigned long id)
{}
void initialize_downtime_data();
void register_downtime();
void schedule_downtime();
void unschedule_downtime();
*/
