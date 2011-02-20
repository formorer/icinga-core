/*****************************************************************************
 *
 * NEBMODULES.H - Include file for event broker modules
 *
 * Copyright (c) 1999-2009 Ethan Galstad (egalstad@nagios.org)
 * Copyright (c) 2009-2011 Nagios Core Development Team and Community Contributors
 * Copyright (c) 2009-2011 Icinga Development Team (http://www.icinga.org)
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

#ifndef _NEBMODULES_H
#define _NEBMODULES_H

#ifdef __cplusplus
  extern "C" {
#endif

/***** MODULE VERSION INFORMATION *****/

#define NEB_API_VERSION(x) int __neb_api_version = x;
#define CURRENT_NEB_API_VERSION    3



/***** MODULE INFORMATION *****/

#define NEBMODULE_MODINFO_NUMITEMS  6
#define NEBMODULE_MODINFO_TITLE     0
#define NEBMODULE_MODINFO_AUTHOR    1
#define NEBMODULE_MODINFO_COPYRIGHT 2
#define NEBMODULE_MODINFO_VERSION   3
#define NEBMODULE_MODINFO_LICENSE   4
#define NEBMODULE_MODINFO_DESC      5



/***** MODULE LOAD/UNLOAD OPTIONS *****/

#define NEBMODULE_NORMAL_LOAD       0    /* module is being loaded normally */
#define NEBMODULE_REQUEST_UNLOAD    0    /* request module to unload (but don't force it) */
#define NEBMODULE_FORCE_UNLOAD      1    /* force module to unload */



/***** MODULES UNLOAD REASONS *****/

#define NEBMODULE_NEB_SHUTDOWN      1    /* event broker is shutting down */
#define NEBMODULE_NEB_RESTART       2    /* event broker is restarting */
#define NEBMODULE_ERROR_NO_INIT     3    /* _module_init() function was not found in module */
#define NEBMODULE_ERROR_BAD_INIT    4    /* _module_init() function returned a bad code */
#define NEBMODULE_ERROR_API_VERSION 5    /* module version is incompatible with current api */



/***** MODULE STRUCTURES *****/
    typedef     int (*mod_initfunc_ptr_t)(int,char *,void *);
    typedef     int (*mod_deinitfunc_ptr_t)(int,int);


#ifdef USE_LTDL
    typedef lt_dlhandle  module_handle_t;
    typedef lt_ptr       module_func_ptr_t;
#else
    typedef void   *     module_handle_t;
    typedef void   *     module_func_ptr_t;
#endif

extern      mod_initfunc_ptr_t          init_func_test;
extern      mod_deinitfunc_ptr_t       deinit_func_test;
    
/* NEB module structure */
    typedef struct nebmodule_struct{
      char            *filename;
      char            *args;
      char            *info[NEBMODULE_MODINFO_NUMITEMS];
      int             should_be_loaded;
      int             is_currently_loaded;
#ifdef USE_LTDL
      lt_dlhandle                 module_handle;
      mod_initfunc_ptr_t          init_func;
      mod_deinitfunc_ptr_t        deinit_func;
#else
      module_handle_t     module_handle;
      mod_initfunc_ptr_t    init_func;
      mod_deinitfunc_ptr_t deinit_func;
#endif
#ifdef HAVE_PTHREAD_H
      pthread_t       thread_id;
#endif
      struct nebmodule_struct *next;
    }nebmodule;


    int assign_mod_initfunc_ptr(nebmodule * pmodule,module_func_ptr_t pfunc);
    int assign_mod_deinitfunc_ptr(nebmodule *pmodule,module_func_ptr_t pfunc);
    
    
    /***** MODULE FUNCTIONS *****/
    int neb_set_module_info(void *,int,char *);

#ifdef __cplusplus
  }
#endif

#endif
