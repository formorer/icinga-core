/*****************************************************************************
 *
 * XSDDEFAULT.C - Default external status data input routines for Nagios
 *
 * Copyright (c) 2000-2003 Ethan Galstad (nagios@nagios.org)
 * Last Modified:   02-20-2003
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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


/*********** COMMON HEADER FILES ***********/

#include "../common/config.h"
#include "../common/common.h"
#include "../common/locations.h"
#include "../common/statusdata.h"

#ifdef NSCORE
#include "../base/nagios.h"
#endif

#ifdef NSCGI
#include "../cgi/cgiutils.h"
#endif


/**** IMPLEMENTATION SPECIFIC HEADER FILES ****/
#include "xsddefault.h"



#ifdef NSCGI
time_t program_start;
int daemon_mode;
time_t last_command_check;
time_t last_log_rotation;
int enable_notifications;
int execute_service_checks;
int accept_passive_service_checks;
int execute_host_checks;
int accept_passive_host_checks;
int enable_event_handlers;
int obsess_over_services;
int obsess_over_hosts;
int enable_flap_detection;
int enable_failure_prediction;
int process_performance_data;
int nagios_pid;
#endif

#ifdef NSCORE
extern time_t program_start;
extern int nagios_pid;
extern int daemon_mode;
extern time_t last_command_check;
extern time_t last_log_rotation;
extern int enable_notifications;
extern int execute_service_checks;
extern int accept_passive_service_checks;
extern int execute_host_checks;
extern int accept_passive_host_checks;
extern int enable_event_handlers;
extern int obsess_over_services;
extern int obsess_over_hosts;
extern int enable_flap_detection;
extern int enable_failure_prediction;
extern int process_performance_data;
extern int aggregate_status_updates;
#endif


char xsddefault_status_log[MAX_FILENAME_LENGTH]="";
char xsddefault_temp_file[MAX_FILENAME_LENGTH]="";

#ifdef NSCORE
char xsddefault_aggregate_temp_file[MAX_INPUT_BUFFER];
#endif



/******************************************************************/
/***************** COMMON CONFIG INITIALIZATION  ******************/
/******************************************************************/

/* grab configuration information */
int xsddefault_grab_config_info(char *config_file){
	char input_buffer[MAX_INPUT_BUFFER];
	FILE *fp;
#ifdef NSCGI
	FILE *fp2;
	char *temp_buffer;
#endif


	/*** CORE PASSES IN MAIN CONFIG FILE, CGIS PASS IN CGI CONFIG FILE! ***/

	/* initialize the location of the status log */
	strncpy(xsddefault_status_log,DEFAULT_STATUS_FILE,sizeof(xsddefault_status_log)-1);
	strncpy(xsddefault_temp_file,DEFAULT_TEMP_FILE,sizeof(xsddefault_temp_file)-1);
	xsddefault_status_log[sizeof(xsddefault_status_log)-1]='\x0';
	xsddefault_temp_file[sizeof(xsddefault_temp_file)-1]='\x0';

	/* open the config file for reading */
	fp=fopen(config_file,"r");
	if(fp==NULL)
		return ERROR;

	/* read in all lines from the main config file */
	for(fgets(input_buffer,sizeof(input_buffer)-1,fp);!feof(fp);fgets(input_buffer,sizeof(input_buffer)-1,fp)){

		/* skip blank lines and comments */
		if(input_buffer[0]=='#' || input_buffer[0]=='\x0' || input_buffer[0]=='\n' || input_buffer[0]=='\r')
			continue;

		strip(input_buffer);

#ifdef NSCGI
		/* CGI needs to find and read contents of main config file, since it was passed the name of the CGI config file */
		if(strstr(input_buffer,"main_config_file")==input_buffer){

			temp_buffer=strtok(input_buffer,"=");
			temp_buffer=strtok(NULL,"\n");
			if(temp_buffer==NULL)
				continue;
			
			fp2=fopen(temp_buffer,"r");
			if(fp2==NULL)
				continue;

			/* read in all lines from the main config file */
			for(fgets(input_buffer,sizeof(input_buffer)-1,fp2);!feof(fp2);fgets(input_buffer,sizeof(input_buffer)-1,fp2)){

				/* skip blank lines and comments */
				if(input_buffer[0]=='#' || input_buffer[0]=='\x0' || input_buffer[0]=='\n' || input_buffer[0]=='\r')
					continue;

				strip(input_buffer);

				xsddefault_grab_config_directives(input_buffer);
			        }

			fclose(fp2);
		        }
#endif

#ifdef NSCORE
		/* core reads variables directly from the main config file */
		xsddefault_grab_config_directives(input_buffer);
#endif
	        }

	fclose(fp);

	/* we didn't find the status log name */
	if(!strcmp(xsddefault_status_log,""))
		return ERROR;

	/* we didn't find the temp file */
	if(!strcmp(xsddefault_temp_file,""))
		return ERROR;

	return OK;
        }


void xsddefault_grab_config_directives(char *input_buffer){
	char *temp_buffer;

	/* status log definition */
	if((strstr(input_buffer,"status_file")==input_buffer) || (strstr(input_buffer,"xsddefault_status_log")==input_buffer)){
		temp_buffer=strtok(input_buffer,"=");
		temp_buffer=strtok(NULL,"\n");
		if(temp_buffer==NULL)
			return;
		strncpy(xsddefault_status_log,temp_buffer,sizeof(xsddefault_status_log)-1);
		xsddefault_status_log[sizeof(xsddefault_status_log)-1]='\x0';
	        }


	/* temp file definition */
	if((strstr(input_buffer,"temp_file")==input_buffer) || (strstr(input_buffer,"xsddefault_temp_file")==input_buffer)){
		temp_buffer=strtok(input_buffer,"=");
		temp_buffer=strtok(NULL,"\n");
		if(temp_buffer==NULL)
			return;
		strncpy(xsddefault_temp_file,temp_buffer,sizeof(xsddefault_temp_file)-1);
		xsddefault_temp_file[sizeof(xsddefault_temp_file)-1]='\x0';
	        }

	return;
        }



#ifdef NSCORE

/******************************************************************/
/********************* INIT/CLEANUP FUNCTIONS *********************/
/******************************************************************/


/* initialize status data */
int xsddefault_initialize_status_data(char *config_file){
	int result;

	/* grab configuration data */
	result=xsddefault_grab_config_info(config_file);
	if(result==ERROR)
		return ERROR;

	/* delete the old status log (it might not exist) */
	unlink(xsddefault_status_log);

	return OK;
        }


/* cleanup status data before terminating */
int xsddefault_cleanup_status_data(char *config_file, int delete_status_data){

	/* delete the status log */
	if(delete_status_data==TRUE){
		if(unlink(xsddefault_status_log))
			return ERROR;
	        }

	return OK;
        }


/******************************************************************/
/****************** STATUS DATA OUTPUT FUNCTIONS ******************/
/******************************************************************/

/* write all status data to file */
int xsddefault_save_status_data(void){
	char buffer[MAX_INPUT_BUFFER];
	host *temp_host;
	service *temp_service;
	void *host_cursor;
	time_t current_time;
	int fd=0;
	FILE *fp=NULL;
	int x;

	/* open a safe temp file for output */
	snprintf(xsddefault_aggregate_temp_file,sizeof(xsddefault_aggregate_temp_file)-1,"%sXXXXXX",xsddefault_temp_file);
	xsddefault_aggregate_temp_file[sizeof(xsddefault_aggregate_temp_file)-1]='\x0';
	if((fd=mkstemp(xsddefault_aggregate_temp_file))==-1)
		return ERROR;
	fp=fdopen(fd,"w");
	if(fp==NULL){
		close(fd);
		unlink(xsddefault_aggregate_temp_file);
		return ERROR;
	        }

	/* write version info to status file */
	fprintf(fp,"########################################\n");
	fprintf(fp,"#          NAGIOS STATUS FILE\n");
	fprintf(fp,"#\n");
	fprintf(fp,"# THIS FILE IS AUTOMATICALLY GENERATED\n");
	fprintf(fp,"# BY NAGIOS.  DO NOT MODIFY THIS FILE!\n");
	fprintf(fp,"########################################\n\n");

	time(&current_time);

	/* write file info */
	fprintf(fp,"info {\n");
	fprintf(fp,"\tcreated=%lu\n",current_time);
	fprintf(fp,"\tversion=%s\n",PROGRAM_VERSION);
	fprintf(fp,"\t}\n\n");

	/* save program status data */
	fprintf(fp,"program {\n");
	fprintf(fp,"\tnagios_pid=%d\n",nagios_pid);
	fprintf(fp,"\tdaemon_mode=%d\n",daemon_mode);
	fprintf(fp,"\tprogram_start=%lu\n",program_start);
	fprintf(fp,"\tlast_command_check=%lu\n",last_command_check);
	fprintf(fp,"\tlast_log_rotation=%lu\n",last_log_rotation);
	fprintf(fp,"\tenable_notifications=%d\n",enable_notifications);
	fprintf(fp,"\tactive_service_checks_enabled=%d\n",execute_service_checks);
	fprintf(fp,"\tpassive_service_checks_enabled=%d\n",accept_passive_service_checks);
	fprintf(fp,"\tactive_host_checks_enabled=%d\n",execute_host_checks);
	fprintf(fp,"\tpassive_host_checks_enabled=%d\n",accept_passive_host_checks);
	fprintf(fp,"\tenable_event_handlers=%d\n",enable_event_handlers);
	fprintf(fp,"\tobsess_over_services=%d\n",obsess_over_services);
	fprintf(fp,"\tobsess_over_hosts=%d\n",obsess_over_hosts);
	fprintf(fp,"\tenable_flap_detection=%d\n",enable_flap_detection);
	fprintf(fp,"\tenable_failure_prediction=%d\n",enable_failure_prediction);
	fprintf(fp,"\tprocess_performance_data=%d\n",process_performance_data);
	fprintf(fp,"\t}\n\n");


	/* save host status data */
	host_cursor=get_host_cursor();
	while((temp_host=get_next_host_cursor(host_cursor))!=NULL){

		fprintf(fp,"host {\n");
		fprintf(fp,"\thost_name=%s\n",temp_host->name);
		fprintf(fp,"\thas_been_checked=%d\n",temp_host->has_been_checked);
		fprintf(fp,"\tshould_be_scheduled=%d\n",temp_host->should_be_scheduled);
		fprintf(fp,"\tcheck_execution_time=%.2f\n",temp_host->execution_time);
		fprintf(fp,"\tcheck_latency=%lu\n",temp_host->latency);
		fprintf(fp,"\tcurrent_state=%d\n",temp_host->current_state);
		fprintf(fp,"\tlast_hard_state=%d\n",temp_host->last_hard_state);
		fprintf(fp,"\tcheck_type=%d\n",temp_host->check_type);
		fprintf(fp,"\tplugin_output=%s\n",(temp_host->plugin_output==NULL)?"":temp_host->plugin_output);
		fprintf(fp,"\tperformance_data=%s\n",(temp_host->perf_data==NULL)?"":temp_host->perf_data);
		fprintf(fp,"\tlast_check=%lu\n",temp_host->last_check);
		fprintf(fp,"\tnext_check=%lu\n",temp_host->next_check);
		fprintf(fp,"\tcurrent_attempt=%d\n",temp_host->current_attempt);
		fprintf(fp,"\tmax_attempts=%d\n",temp_host->max_attempts);
		fprintf(fp,"\tstate_type=%d\n",temp_host->state_type);
		fprintf(fp,"\tlast_state_change=%lu\n",temp_host->last_state_change);
		fprintf(fp,"\tlast_notification=%lu\n",temp_host->last_host_notification);
		fprintf(fp,"\tcurrent_notification_number=%d\n",temp_host->current_notification_number);
		fprintf(fp,"\tnotifications_enabled=%d\n",temp_host->notifications_enabled);
		fprintf(fp,"\tproblem_has_been_acknowledged=%d\n",temp_host->problem_has_been_acknowledged);
		fprintf(fp,"\tactive_checks_enabled=%d\n",temp_host->checks_enabled);
		fprintf(fp,"\tpassive_checks_enabled=%d\n",temp_host->accept_passive_host_checks);
		fprintf(fp,"\tevent_handler_enabled=%d\n",temp_host->event_handler_enabled);
		fprintf(fp,"\tflap_detection_enabled=%d\n",temp_host->flap_detection_enabled);
		fprintf(fp,"\tfailure_prediction_enabled=%d\n",temp_host->failure_prediction_enabled);
		fprintf(fp,"\tprocess_performance_data=%d\n",temp_host->process_performance_data);
		fprintf(fp,"\tobsess_over_host=%d\n",temp_host->obsess_over_host);
		fprintf(fp,"\tlast_update=%lu\n",current_time);
		fprintf(fp,"\tis_flapping=%d\n",temp_host->is_flapping);
		fprintf(fp,"\tpercent_state_change=%.2f\n",temp_host->percent_state_change);
		fprintf(fp,"\tscheduled_downtime_depth=%d\n",temp_host->scheduled_downtime_depth);
		/*
		fprintf(fp,"\tstate_history=");
		for(x=0;x<MAX_STATE_HISTORY_ENTRIES;x++)
			fprintf(fp,"%s%d",(x>0)?",":"",temp_host->state_history[(x+temp_host->state_history_index)%MAX_STATE_HISTORY_ENTRIES]);
		fprintf(fp,"\n");
		*/
		fprintf(fp,"\t}\n\n");
	        }
	free_host_cursor(host_cursor);

	/* save service status data */
	move_first_service();
	while((temp_service=get_next_service())!=NULL){

		fprintf(fp,"service {\n");
		fprintf(fp,"\thost_name=%s\n",temp_service->host_name);
		fprintf(fp,"\tservice_description=%s\n",temp_service->description);
		fprintf(fp,"\thas_been_checked=%d\n",temp_service->has_been_checked);
		fprintf(fp,"\tshould_be_scheduled=%d\n",temp_service->should_be_scheduled);
		fprintf(fp,"\tcheck_execution_time=%.2f\n",temp_service->execution_time);
		fprintf(fp,"\tcheck_latency=%lu\n",temp_service->latency);
		fprintf(fp,"\tcurrent_state=%d\n",temp_service->current_state);
		fprintf(fp,"\tlast_hard_state=%d\n",temp_service->last_hard_state);
		fprintf(fp,"\tcurrent_attempt=%d\n",temp_service->current_attempt);
		fprintf(fp,"\tmax_attempts=%d\n",temp_service->max_attempts);
		fprintf(fp,"\tstate_type=%d\n",temp_service->state_type);
		fprintf(fp,"\tlast_state_change=%lu\n",temp_service->last_state_change);
		fprintf(fp,"\tplugin_output=%s\n",(temp_service->plugin_output==NULL)?"":temp_service->plugin_output);
		fprintf(fp,"\tperformance_data=%s\n",(temp_service->perf_data==NULL)?"":temp_service->perf_data);
		fprintf(fp,"\tlast_check=%lu\n",temp_service->last_check);
		fprintf(fp,"\tnext_check=%lu\n",temp_service->next_check);
		fprintf(fp,"\tcheck_type=%d\n",temp_service->check_type);
		fprintf(fp,"\tcurrent_notification_number=%d\n",temp_service->current_notification_number);
		fprintf(fp,"\tlast_notification=%lu\n",temp_service->last_notification);
		fprintf(fp,"\tnotifications_enabled=%d\n",temp_service->notifications_enabled);
		fprintf(fp,"\tactive_checks_enabled=%d\n",temp_service->checks_enabled);
		fprintf(fp,"\tpassive_checks_enabled=%d\n",temp_service->accept_passive_service_checks);
		fprintf(fp,"\tevent_handler_enabled=%d\n",temp_service->event_handler_enabled);
		fprintf(fp,"\tproblem_has_been_acknowledged=%d\n",temp_service->problem_has_been_acknowledged);
		fprintf(fp,"\tflap_detection_enabled=%d\n",temp_service->flap_detection_enabled);
		fprintf(fp,"\tfailure_prediction_enabled=%d\n",temp_service->failure_prediction_enabled);
		fprintf(fp,"\tprocess_performance_data=%d\n",temp_service->process_performance_data);
		fprintf(fp,"\tobsess_over_service=%d\n",temp_service->obsess_over_service);
		fprintf(fp,"\tlast_update=%lu\n",current_time);
		fprintf(fp,"\tis_flapping=%d\n",temp_service->is_flapping);
		fprintf(fp,"\tpercent_state_change=%.2f\n",temp_service->percent_state_change);
		fprintf(fp,"\tscheduled_downtime_depth=%d\n",temp_service->scheduled_downtime_depth);
		/*
		fprintf(fp,"\tstate_history=");
		for(x=0;x<MAX_STATE_HISTORY_ENTRIES;x++)
			fprintf(fp,"%s%d",(x>0)?",":"",temp_service->state_history[(x+temp_service->state_history_index)%MAX_STATE_HISTORY_ENTRIES]);
		fprintf(fp,"\n");
		*/
		fprintf(fp,"\t}\n\n");
	        }


	/* reset file permissions */
	fchmod(fd,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

	/* close the temp file */
	fclose(fp);

	/* move the temp file to the status log (overwrite the old status log) */
	if(my_rename(xsddefault_aggregate_temp_file,xsddefault_status_log))
		return ERROR;

	return OK;
        }

#endif



#ifdef NSCGI

/******************************************************************/
/****************** DEFAULT DATA INPUT FUNCTIONS ******************/
/******************************************************************/

/* read all program, host, and service status information */
int xsddefault_read_status_data(char *config_file,int options){
	char temp_buffer[MAX_INPUT_BUFFER];
	char *temp_ptr;
	FILE *fp;
	int data_type=XSDDEFAULT_NO_DATA;
	int x;
	hoststatus *temp_hoststatus=NULL;
	servicestatus *temp_servicestatus=NULL;
	char *var;
	char *val;
	int result;

	/* grab configuration data */
	result=xsddefault_grab_config_info(config_file);
	if(result==ERROR)
		return ERROR;

	/* opent the status log for reading */
	fp=fopen(xsddefault_status_log,"r");
	if(fp==NULL)
		return ERROR;

	/* read all lines in the retention file */
	while(fgets(temp_buffer,sizeof(temp_buffer)-1,fp)){

		strip(temp_buffer);

		/* skip blank lines and comments */
		if(temp_buffer[0]=='#' || temp_buffer[0]=='\x0')
			continue;

		else if(!strcmp(temp_buffer,"info {"))
			data_type=XSDDEFAULT_INFO_DATA;
		else if(!strcmp(temp_buffer,"program {"))
			data_type=XSDDEFAULT_PROGRAM_DATA;
		else if(!strcmp(temp_buffer,"host {")){
			data_type=XSDDEFAULT_HOST_DATA;
			temp_hoststatus=(hoststatus *)malloc(sizeof(hoststatus));
			if(temp_hoststatus){
				temp_hoststatus->host_name=NULL;
				temp_hoststatus->plugin_output=NULL;
				temp_hoststatus->perf_data=NULL;
			        }
		        }
		else if(!strcmp(temp_buffer,"service {")){
			data_type=XSDDEFAULT_SERVICE_DATA;
			temp_servicestatus=(servicestatus *)malloc(sizeof(servicestatus));
			if(temp_servicestatus){
				temp_servicestatus->host_name=NULL;
				temp_servicestatus->description=NULL;
				temp_servicestatus->plugin_output=NULL;
				temp_servicestatus->perf_data=NULL;
			        }
		        }

		else if(!strcmp(temp_buffer,"}")){

			switch(data_type){

			case XSDDEFAULT_INFO_DATA:
				break;

			case XSDDEFAULT_PROGRAM_DATA:
				break;

			case XSDDEFAULT_HOST_DATA:
				add_host_status(temp_hoststatus);
				temp_hoststatus=NULL;
				break;

			case XSDDEFAULT_SERVICE_DATA:
				add_service_status(temp_servicestatus);
				temp_servicestatus=NULL;
				break;

			default:
				break;
			        }

			data_type=XSDDEFAULT_NO_DATA;
		        }

		else if(data_type!=XSDDEFAULT_NO_DATA){

			var=strtok(temp_buffer,"=");
			val=strtok(NULL,"\n");
			if(val==NULL)
				continue;

			switch(data_type){

			case XSDDEFAULT_INFO_DATA:
				break;

			case XSDDEFAULT_PROGRAM_DATA:
				if(!strcmp(var,"nagios_pid"))
					nagios_pid=atoi(val);
				else if(!strcmp(var,"daemon_mode"))
					daemon_mode=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"program_start"))
					program_start=strtoul(val,NULL,10);
				else if(!strcmp(var,"last_command_check"))
					last_command_check=strtoul(val,NULL,10);
				else if(!strcmp(var,"last_log_rotation"))
					last_log_rotation=strtoul(val,NULL,10);
				else if(!strcmp(var,"enable_notifications"))
					enable_notifications=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"active_service_checks_enabled"))
					execute_service_checks=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"passive_service_checks_enabled"))
					accept_passive_service_checks=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"active_host_checks_enabled"))
					execute_host_checks=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"passive_host_checks_enabled"))
					accept_passive_host_checks=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"enable_event_handlers"))
					enable_event_handlers=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"obsess_over_services"))
					obsess_over_services=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"obsess_over_hosts"))
					obsess_over_hosts=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"enable_flap_detection"))
					enable_flap_detection=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"enable_failure_prediction"))
					enable_failure_prediction=(atoi(val)>0)?TRUE:FALSE;
				else if(!strcmp(var,"process_performance_data"))
					process_performance_data=(atoi(val)>0)?TRUE:FALSE;
				break;

			case XSDDEFAULT_HOST_DATA:
				if(temp_hoststatus!=NULL){
					if(!strcmp(var,"host_name"))
						temp_hoststatus->host_name=strdup(val);
					else if(!strcmp(var,"has_been_checked"))
						temp_hoststatus->has_been_checked=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"should_be_scheduled"))
						temp_hoststatus->should_be_scheduled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"check_execution_time"))
						temp_hoststatus->execution_time=strtod(val,NULL);
					else if(!strcmp(var,"check_latency"))
						temp_hoststatus->latency=strtoul(val,NULL,10);
					else if(!strcmp(var,"current_state"))
						temp_hoststatus->status=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"last_hard_state"))
						temp_hoststatus->last_hard_state=atoi(val);
					else if(!strcmp(var,"plugin_output"))
						temp_hoststatus->plugin_output=strdup(val);
					else if(!strcmp(var,"performance_data"))
						temp_hoststatus->perf_data=strdup(val);
					else if(!strcmp(var,"current_attempt"))
						temp_hoststatus->current_attempt=atoi(val);
					else if(!strcmp(var,"max_attempts"))
						temp_hoststatus->max_attempts=atoi(val);
					else if(!strcmp(var,"last_check"))
						temp_hoststatus->last_check=strtoul(val,NULL,10);
					else if(!strcmp(var,"next_check"))
						temp_hoststatus->next_check=strtoul(val,NULL,10);
					else if(!strcmp(var,"check_type"))
						temp_hoststatus->check_type=atoi(val);
					else if(!strcmp(var,"current_attempt"))
						temp_hoststatus->current_attempt=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"state_type"))
						temp_hoststatus->state_type=atoi(val);
					else if(!strcmp(var,"last_state_change"))
						temp_hoststatus->last_state_change=strtoul(val,NULL,10);
					else if(!strcmp(var,"last_notification"))
						temp_hoststatus->last_notification=strtoul(val,NULL,10);
					else if(!strcmp(var,"current_notification_number"))
						temp_hoststatus->current_notification_number=atoi(val);
					else if(!strcmp(var,"notifications_enabled"))
						temp_hoststatus->notifications_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"problem_has_been_acknowledged"))
						temp_hoststatus->problem_has_been_acknowledged=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"active_checks_enabled"))
						temp_hoststatus->checks_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"passive_checks_enabled"))
						temp_hoststatus->accept_passive_host_checks=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"event_handler_enabled"))
						temp_hoststatus->event_handler_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"flap_detection_enabled"))
						temp_hoststatus->flap_detection_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"failure_prediction_enabled"))
						temp_hoststatus->failure_prediction_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"process_performance_data"))
						temp_hoststatus->process_performance_data=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"obsess_over_host"))
						temp_hoststatus->obsess_over_host=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"last_update"))
						temp_hoststatus->last_update=strtoul(val,NULL,10);
					else if(!strcmp(var,"is_flapping"))
						temp_hoststatus->is_flapping=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"percent_state_change"))
						temp_hoststatus->percent_state_change=strtod(val,NULL);
					else if(!strcmp(var,"scheduled_downtime_depth"))
						temp_hoststatus->scheduled_downtime_depth=atoi(val);
					/*
					else if(!strcmp(var,"state_history")){
						temp_ptr=val;
						for(x=0;x<MAX_STATE_HISTORY_ENTRIES;x++)
							temp_hoststatus->state_history[x]=atoi(strsep(&temp_ptr,","));
						temp_hoststatus->state_history_index=0;
					        }
					*/
				        }
				break;

			case XSDDEFAULT_SERVICE_DATA:
				if(temp_servicestatus!=NULL){
					if(!strcmp(var,"host_name"))
						temp_servicestatus->host_name=strdup(val);
					else if(!strcmp(var,"service_description"))
						temp_servicestatus->description=strdup(val);
					else if(!strcmp(var,"has_been_checked"))
						temp_servicestatus->has_been_checked=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"should_be_scheduled"))
						temp_servicestatus->should_be_scheduled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"check_execution_time"))
						temp_servicestatus->execution_time=strtod(val,NULL);
					else if(!strcmp(var,"check_latency"))
						temp_servicestatus->latency=strtoul(val,NULL,10);
					else if(!strcmp(var,"current_state"))
						temp_servicestatus->status=atoi(val);
					else if(!strcmp(var,"last_hard_state"))
						temp_servicestatus->last_hard_state=atoi(val);
					else if(!strcmp(var,"current_attempt"))
						temp_servicestatus->current_attempt=atoi(val);
					else if(!strcmp(var,"max_attempts"))
						temp_servicestatus->max_attempts=atoi(val);
					else if(!strcmp(var,"state_type"))
						temp_servicestatus->state_type=atoi(val);
					else if(!strcmp(var,"last_state_change"))
						temp_servicestatus->last_state_change=strtoul(val,NULL,10);
					else if(!strcmp(var,"plugin_output"))
						temp_servicestatus->plugin_output=strdup(val);
					else if(!strcmp(var,"performance_data"))
						temp_servicestatus->perf_data=strdup(val);
					else if(!strcmp(var,"last_check"))
						temp_servicestatus->last_check=strtoul(val,NULL,10);
					else if(!strcmp(var,"next_check"))
						temp_servicestatus->next_check=strtoul(val,NULL,10);
					else if(!strcmp(var,"check_type"))
						temp_servicestatus->check_type=atoi(val);
					else if(!strcmp(var,"current_notification_number"))
						temp_servicestatus->current_notification_number=atoi(val);
					else if(!strcmp(var,"last_notification"))
						temp_servicestatus->last_notification=strtoul(val,NULL,10);
					else if(!strcmp(var,"notifications_enabled"))
						temp_servicestatus->notifications_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"active_checks_enabled"))
						temp_servicestatus->checks_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"passive_checks_enabled"))
						temp_servicestatus->accept_passive_service_checks=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"event_handler_enabled"))
						temp_servicestatus->event_handler_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"problem_has_been_acknowledged"))
						temp_servicestatus->problem_has_been_acknowledged=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"flap_detection_enabled"))
						temp_servicestatus->flap_detection_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"failure_prediction_enabled"))
						temp_servicestatus->failure_prediction_enabled=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"process_performance_data"))
						temp_servicestatus->process_performance_data=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"obsess_over_service"))
						temp_servicestatus->obsess_over_service=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"last_update"))
						temp_servicestatus->last_update=strtoul(val,NULL,10);
					else if(!strcmp(var,"is_flapping"))
						temp_servicestatus->is_flapping=(atoi(val)>0)?TRUE:FALSE;
					else if(!strcmp(var,"percent_state_change"))
						temp_servicestatus->percent_state_change=strtod(val,NULL);
					else if(!strcmp(var,"scheduled_downtime_depth"))
						temp_servicestatus->scheduled_downtime_depth=atoi(val);
					/*
					else if(!strcmp(var,"state_history")){
						temp_ptr=val;
						for(x=0;x<MAX_STATE_HISTORY_ENTRIES;x++)
							temp_servicestatus->state_history[x]=atoi(strsep(&temp_ptr,","));
						temp_servicestatus->state_history_index=0;
					        }
					*/
				        }
				break;

			default:
				break;
			        }

		        }
	        }

	fclose(fp);

	return OK;
        }

#endif

