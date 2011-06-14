/*****************************************************************************
 *
 * CGIAUTH.C - Authorization utilities for Icinga CGIs
 *
 * Copyright (c) 1999-2008 Ethan Galstad (egalstad@nagios.org)
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

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"

#include "../include/cgiutils.h"
#include "../include/cgiauth.h"

extern char            main_config_file[MAX_FILENAME_LENGTH];

extern hostgroup       *hostgroup_list;
extern servicegroup    *servicegroup_list;

extern int             use_authentication;
extern int             use_ssl_authentication;

extern int	       show_all_services_host_is_authorized_for;

/* get current authentication information */
int get_authentication_information(authdata *authinfo){
	mmapfile *thefile;
	char *input=NULL;
	char *temp_ptr;

	if(authinfo==NULL)
		return ERROR;

	/* initial values... */
	authinfo->authorized_for_all_hosts=FALSE;
	authinfo->authorized_for_all_host_commands=FALSE;
	authinfo->authorized_for_all_services=FALSE;
	authinfo->authorized_for_all_service_commands=FALSE;
	authinfo->authorized_for_system_information=FALSE;
	authinfo->authorized_for_system_commands=FALSE;
	authinfo->authorized_for_configuration_information=FALSE;
	authinfo->authorized_for_read_only=FALSE;
	authinfo->number_of_authentication_rules=0;
	authinfo->authentication_rules=NULL;

	/* grab username from the environment... */
	if(use_ssl_authentication) {
		/* patch by Pawl Zuzelski - 7/22/08 */
		temp_ptr=getenv("SSL_CLIENT_S_DN_CN");
	}
	else{
		temp_ptr=getenv("REMOTE_USER");
	}
	if(temp_ptr==NULL){
		authinfo->username="";
		authinfo->authenticated=FALSE;
	}
	else{
		authinfo->username=(char *)malloc(strlen(temp_ptr)+1);
		if(authinfo->username==NULL)
			authinfo->username="";
		else
			strcpy(authinfo->username,temp_ptr);
		if(!strcmp(authinfo->username,""))
			authinfo->authenticated=FALSE;
		else
			authinfo->authenticated=TRUE;
	}

	/* read in authorization override vars from config file... */
	if((thefile=mmap_fopen(get_cgi_config_location()))!=NULL){

		while(1){

			/* free memory */
			free(input);

			/* read the next line */
			if((input=mmap_fgets_multiline(thefile))==NULL)
				break;

			strip(input);

			/* we don't have a username yet, so fake the authentication if we find a default username defined */
			if(!strcmp(authinfo->username,"") && strstr(input,"default_user_name=")==input){
				temp_ptr=strtok(input,"=");
				temp_ptr=strtok(NULL,",");

				if(temp_ptr==NULL){
					authinfo->username="";
					authinfo->authenticated=FALSE;
				}
				else{
					authinfo->username=(char *)malloc(strlen(temp_ptr)+1);
					if(authinfo->username==NULL)
						authinfo->username="";
					else
						strcpy(authinfo->username,temp_ptr);
					if(!strcmp(authinfo->username,""))
						authinfo->authenticated=FALSE;
					else
						authinfo->authenticated=TRUE;
				}
		        }

			else if(strstr(input,"authorized_for_all_hosts=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_all_hosts=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_all_services=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_all_services=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_system_information=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_system_information=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_configuration_information=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_configuration_information=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_all_host_commands=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_all_host_commands=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_all_service_commands=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_all_service_commands=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_system_commands=")==input){
				temp_ptr=strtok(input,"=");
				while((temp_ptr=strtok(NULL,","))){
					if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
						authinfo->authorized_for_system_commands=TRUE;
			        }
		        }
			else if(strstr(input,"authorized_for_read_only=")==input){
                                temp_ptr=strtok(input,"=");
                                while((temp_ptr=strtok(NULL,","))){
                                        if(!strcmp(temp_ptr,authinfo->username) || !strcmp(temp_ptr,"*"))
                                                authinfo->authorized_for_read_only=TRUE;
                        	}
                        }
			else if(strstr(input,"authorization_config_file=")==input){
				temp_ptr=strtok(input,"=");
				temp_ptr=strtok(NULL,"\n");
				if(temp_ptr!=NULL)
					parse_authorization_config_file(temp_ptr, authinfo);
			}
		}

		/* free memory and close the file */
		free(input);
		mmap_fclose(thefile);
	}

	if(authinfo->authenticated==TRUE)
		return OK;
	else
		return ERROR;
}

/* parsing authorization configuration file */
int parse_authorization_config_file(char* filename, authdata* authinfo){
	mmapfile *thefile;
	char *input=NULL;
	char *temp_ptr=NULL;
	char *temp_rule=NULL;
	char *role=NULL;
	char *roles=NULL;
	char *roles_tmp=NULL;
	char test_char[2];
	int role_match=FALSE;

	/* Shibboleth environment variable */
	if(getenv("entitlement")==NULL){
		printf("<P><DIV CLASS='errorMessage'>Authorization information: entitlement variable is empty</DIV></P>");
		return ERROR;
	}

	roles=getenv("entitlement");

	roles_tmp=(char *)malloc(strlen(roles)+1);

	/* read in authorization config file */
	if((thefile=mmap_fopen(filename))!=NULL){

		while(1){
			/* read the next line */
			if((input=mmap_fgets_multiline(thefile))==NULL)
				break;

			strip(input);

			test_char[0]=input[0];
			test_char[1]='\0';

			/* ignore comment */
			if(strcmp(test_char,"#")==0)
				continue;

			temp_ptr=strtok(input,"=");

			if(temp_ptr==NULL)
				continue;

			 temp_rule=strtok(NULL,"=");

			if (temp_rule==NULL)
				continue;

			strcpy(roles_tmp,roles);
			role=strtok(roles_tmp,";");

			while(role!=NULL){

				if(strcmp(role,temp_ptr)==0){
					role_match=TRUE;
					break;
				}

				role=strtok(NULL,";");
			}

			if(role_match==FALSE)
				 continue;

			authinfo->number_of_authentication_rules++;
			strip(temp_rule);

			/* increment the authentication_rules array */
			authinfo->authentication_rules=realloc(authinfo->authentication_rules, (sizeof(char*)) * authinfo->number_of_authentication_rules);

			if(authinfo->authentication_rules==NULL)
				return ERROR;

			authinfo->authentication_rules[authinfo->number_of_authentication_rules-1]=malloc(sizeof(char) * (strlen(temp_rule)+1));
			strcpy(authinfo->authentication_rules[authinfo->number_of_authentication_rules-1], temp_rule);
		}

		/* free memory and close the file */
		free(input);
		mmap_fclose(thefile);
	}

	free(roles_tmp);

	return OK;
}

/* set default authz permissions */
int set_authz_permissions(char* permission, authdata* authinfo){

	if(strcmp(permission,"r")==0){ /* only read permissions */
		authinfo->authorized_for_read_only=TRUE;
		authinfo->authorized_for_system_information=TRUE;
		authinfo->authorized_for_configuration_information=TRUE;
		authinfo->authorized_for_system_commands=FALSE;
		authinfo->authorized_for_all_service_commands=FALSE;
		authinfo->authorized_for_all_host_commands=FALSE;
	} else if(strcmp(permission,"w")==0){ /* read + write permissions */
		authinfo->authorized_for_read_only=FALSE;
		authinfo->authorized_for_system_information=TRUE;
		authinfo->authorized_for_system_commands=TRUE;
		authinfo->authorized_for_configuration_information=TRUE;
		authinfo->authorized_for_all_service_commands=TRUE;
		authinfo->authorized_for_all_host_commands=TRUE;
	}

	return TRUE;
}

/* check if user is authorized to view information about a particular host */
int is_authorized_for_host(host *hst, authdata *authinfo){
	contact *temp_contact;
	char *host_list=NULL;
	char *host_list2=NULL;
	char *list_tmp=NULL;
	char *list_tmp2=NULL;
	char *host2=NULL;
	char *tmp=NULL;
	char *tmp_permission=NULL;
	char *tmp_service=NULL;
	char *hg_name=NULL;
	int i;
	int j;
	char permission[2];
	int ok=FALSE;
	int is_ok=FALSE;

	if(hst==NULL)
		return FALSE;

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	/* if this user is authorized for all hosts, they are for this one... */
	if(is_authorized_for_all_hosts(authinfo)==TRUE)
		return TRUE;

	/* find the contact */
	temp_contact=find_contact(authinfo->username);

	/* see if this user is a contact for the host */
	if(is_contact_for_host(hst,temp_contact)==TRUE)
		return TRUE;

	/* see if this user is an escalated contact for the host */
	if(is_escalated_contact_for_host(hst,temp_contact)==TRUE)
		return TRUE;

	/* authz parsing */
	if(authinfo->number_of_authentication_rules!=0){

		strcpy(permission, "r");

		for(i=0; i<authinfo->number_of_authentication_rules; i++){

			list_tmp=malloc(strlen(authinfo->authentication_rules[i])+1);
			strcpy(list_tmp, authinfo->authentication_rules[i]);
			strip(list_tmp);

			/* for this situation: :service:r */
			if(list_tmp[0]==':')
				continue;

			/* "w" is the maximum  permission, do not need continue */
			if(strcmp(permission,"w")==0)
				break;

			host_list=strtok(list_tmp,":");

			host_list2=malloc(strlen(host_list)+1);
			strcpy(host_list2,host_list);

			tmp_service=strtok(NULL,":");
			tmp_permission=strtok(NULL,":");
			host2=strtok(host_list2,",");

			while(host2!=NULL){

				list_tmp2=malloc(strlen(host2)+1);
				strcpy(list_tmp2,host2);
				strip(list_tmp2);

				/* host group parsing */
				if(list_tmp2[0]=='@'){
					hg_name=malloc(strlen(list_tmp2)+1);
					strcpy(hg_name,list_tmp2);

					for(j=0; j<strlen(hg_name); j++)
						hg_name[j]=hg_name[j+1];

					if(is_host_member_of_hostgroup(find_hostgroup(hg_name),hst)==TRUE){
						is_ok=TRUE;
					} else {
						host2=strtok(NULL,",");
						free(hg_name);
						continue;
					}

					free(hg_name);
				}

				if(strcmp(list_tmp2,hst->name)==0 || strcmp(list_tmp2,"*")==0)
					is_ok=TRUE;

				if(is_ok==TRUE){

					/* for this situation: host::r */
					if(tmp_permission==NULL)
						tmp_permission=tmp_service;

					if(tmp_permission!=NULL){
						tmp=malloc(strlen(tmp_permission)+1);
						strcpy(tmp,tmp_permission);
						strip(tmp); /* "w" will overwrite "r" permission */

						if(strcmp(permission,"r")==0 && strcmp(tmp,"w")==0){
							strcpy(permission,"w");
						}

						free(tmp);
					}

					ok=TRUE;
				}

				host2=strtok(NULL,",");
				free(list_tmp2);
			}

			free(list_tmp);
			free(host_list2);
		}

		if(ok==TRUE){
			set_authz_permissions(permission,authinfo);
			return TRUE;
		}

	} /* end of authz parsing */

	return FALSE;
}


/* check if user is authorized to view information about all hosts in a particular hostgroup */
int is_authorized_for_hostgroup(hostgroup *hg, authdata *authinfo){
	hostsmember *temp_hostsmember;
	host *temp_host;

	if(hg==NULL)
		return FALSE;

	/* CHANGED in 2.0 - user must be authorized for ALL hosts in a hostgroup, not just one */
	/* see if user is authorized for all hosts in the hostgroup */
	for(temp_hostsmember=hg->members;temp_hostsmember!=NULL;temp_hostsmember=temp_hostsmember->next){
		temp_host=find_host(temp_hostsmember->host_name);
		if(is_authorized_for_host(temp_host,authinfo)==FALSE)
			return FALSE;
	        }

	return TRUE;
        }



/* check if user is authorized to view information about all services in a particular servicegroup */
int is_authorized_for_servicegroup(servicegroup *sg, authdata *authinfo){
	servicesmember *temp_servicesmember;
	service *temp_service;

	if(sg==NULL)
		return FALSE;

	/* see if user is authorized for all services in the servicegroup */
	for(temp_servicesmember=sg->members;temp_servicesmember!=NULL;temp_servicesmember=temp_servicesmember->next){
		temp_service=find_service(temp_servicesmember->host_name,temp_servicesmember->service_description);
		if(is_authorized_for_service(temp_service,authinfo)==FALSE)
			return FALSE;
	        }

	return TRUE;
        }

/* check if current user is restricted to read only */
int is_authorized_for_read_only(authdata *authinfo){

        /* if we're not using authentication, fake it */
        if(use_authentication==FALSE)
                return FALSE;

        /* if this user has not authenticated return error */
        if(authinfo->authenticated==FALSE)
                return FALSE;

        return authinfo->authorized_for_read_only;
        }

/* check if user is authorized to view information about a particular service */
int is_authorized_for_service(service *svc, authdata *authinfo){
	host *temp_host=NULL;
	contact *temp_contact=NULL;
	char *host_list=NULL;
	char *host_list2=NULL;
	char *service_list=NULL;
	char *list_tmp=NULL;
	char *service=NULL;
	char *host2=NULL;
	char *read_only=NULL;
	char *list_tmp2=NULL;
	char *list_tmp3=NULL;
	char *list_tmp4=NULL;
	char *sg_name=NULL;
	char *hg_name=NULL;
	int i=0;
	int j=0;
	int ok=FALSE;
	int is_ok=FALSE;
	int is_ok2=FALSE;
	char permission[2];

	if(svc==NULL)
		return FALSE;

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	/* if this user is authorized for all services, they are for this one... */
	if(is_authorized_for_all_services(authinfo)==TRUE)
		return TRUE;

	/* find the host */
	temp_host=find_host(svc->host_name);
	if(temp_host==NULL)
		return FALSE;

	/* if this user is authorized for this host, they are for all services on it as well... */
	/* 06-02-2010 added config option, if set FALSE, this condition won't match and
	   user must be authorized for the services too in order to view them 			*/

	if(is_authorized_for_host(temp_host,authinfo)==TRUE){

		/* first off, let attribute based auth decide, then show_all_services_host_is_authorized_for==TRUE */

		/* authz parsing */
		if (authinfo->number_of_authentication_rules!=0){
			strcpy(permission,"r");

			for(i=0; i<authinfo->number_of_authentication_rules; i++){

				/* "w" is the maximum  permission, do not need continue */
				if (strcmp(permission,"w") == 0) break;

				list_tmp=malloc(strlen(authinfo->authentication_rules[i])+1);
				strcpy(list_tmp,authinfo->authentication_rules[i]);

				host_list=strtok(list_tmp,":");

				host_list2=malloc(strlen(host_list)+1);
				strcpy(host_list2,host_list);

				service_list=strtok(NULL,":");
				read_only=strtok(NULL,":");
				service=strtok(service_list,",");

				while (service!=NULL) {
					list_tmp2=malloc(strlen(service)+1);
					strcpy(list_tmp2,service);
					strip(list_tmp2);

					/* service group parsing */
					if (list_tmp2[0]=='@') {
						sg_name=malloc(strlen(list_tmp2)+1);
						strcpy(sg_name,list_tmp2);

						for (j=0; j<strlen(sg_name); j++)
							sg_name[j]=sg_name[j+1];

						if (is_service_member_of_servicegroup(find_servicegroup(sg_name),svc)==TRUE){
							is_ok2=TRUE;
						} else {
							service=strtok(NULL,",");
							free(sg_name);
							continue;
						}

						free(sg_name);
					}

					if (strcmp(list_tmp2,svc->display_name)==0 || strcmp(list_tmp2, "*")==0)
						is_ok2=TRUE;

					if (is_ok2==TRUE){
						host2=strtok(host_list2,",");

						while (host2!=NULL){
							list_tmp3=malloc(strlen(host2)+1);
							strcpy(list_tmp3,host2);
							strip(list_tmp3);

							/* host group parsing */
							if (list_tmp3[0]=='@') {
								hg_name=malloc(strlen(list_tmp3)+1);
								strcpy(hg_name,list_tmp3);

								for (j=0; j<strlen(hg_name); j++)
									hg_name[j]=hg_name[j+1];

								if (is_host_member_of_hostgroup(find_hostgroup(hg_name), temp_host)==TRUE){
									is_ok=TRUE;
								} else {
									host2=strtok(NULL,",");
									free(hg_name);
									continue;
								}

								free(hg_name);
							}

							if (strcmp(list_tmp2,svc->host_name)==0 || strcmp(list_tmp2, "*")==0)
								is_ok=TRUE;

							if (is_ok==TRUE){
								if (read_only!=NULL){
									list_tmp4=malloc(strlen(read_only)+1);
									strcpy(list_tmp4,read_only);
									strip(list_tmp4); /* "w" will overwrite "r" permission */

									if (strcmp(permission,"r")==0 && strcmp(list_tmp4,"w")==0){
										strcpy(permission,"w");
									}

									free(list_tmp4);
								}

								ok=TRUE;
							}

							host2=strtok(NULL,",");
							free(list_tmp3);
						}
					}

					service=strtok(NULL,",");
					free(list_tmp2);
				}

				free(list_tmp);
				free(host_list2);
			}

			if (ok==TRUE){
				set_authz_permissions(permission, authinfo);
				return TRUE;
			}

		} /* end of authz parsing */
		else {
			/* user does not need to be authorized for the services too in order to view them? */
			if(show_all_services_host_is_authorized_for==TRUE){
				return TRUE;
			}
		}
	}

	/* find the contact */
	temp_contact=find_contact(authinfo->username);

	/* see if this user is a contact for the service */
	if(is_contact_for_service(svc,temp_contact)==TRUE)
		return TRUE;

	/* see if this user is an escalated contact for the service */
	if(is_escalated_contact_for_service(svc,temp_contact)==TRUE)
		return TRUE;

	return FALSE;
        }


/* check if current user is authorized to view information on all hosts */
int is_authorized_for_all_hosts(authdata *authinfo){

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	return authinfo->authorized_for_all_hosts;
        }


/* check if current user is authorized to view information on all service */
int is_authorized_for_all_services(authdata *authinfo){

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	return authinfo->authorized_for_all_services;
        }


/* check if current user is authorized to view system information */
int is_authorized_for_system_information(authdata *authinfo){

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	return authinfo->authorized_for_system_information;
        }


/* check if current user is authorized to view configuration information */
int is_authorized_for_configuration_information(authdata *authinfo){

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	return authinfo->authorized_for_configuration_information;
        }


/* check if current user is authorized to issue system commands */
int is_authorized_for_system_commands(authdata *authinfo){

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	return authinfo->authorized_for_system_commands;
        }


/* check is the current user is authorized to issue commands relating to a particular service */
int is_authorized_for_service_commands(service *svc, authdata *authinfo){
	host *temp_host;
	contact *temp_contact;

	if(svc==NULL)
		return FALSE;

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	/* the user is authorized if they have rights to the service */
	if(is_authorized_for_service(svc,authinfo)==TRUE){

		/* find the host */
		temp_host=find_host(svc->host_name);
		if(temp_host==NULL)
			return FALSE;

		/* find the contact */
		temp_contact=find_contact(authinfo->username);

		/* reject if contact is not allowed to issue commands */
		if(temp_contact && temp_contact->can_submit_commands==FALSE)
			return FALSE;

		/* see if this user is a contact for the host */
		if(is_contact_for_host(temp_host,temp_contact)==TRUE)
			return TRUE;

		/* see if this user is an escalated contact for the host */
		if(is_escalated_contact_for_host(temp_host,temp_contact)==TRUE)
			return TRUE;

		/* this user is a contact for the service, so they have permission... */
		if(is_contact_for_service(svc,temp_contact)==TRUE)
			return TRUE;

		/* this user is an escalated contact for the service, so they have permission... */
		if(is_escalated_contact_for_service(svc,temp_contact)==TRUE)
			return TRUE;

		/* this user is not a contact for the host, so they must have been given explicit permissions to all service commands */
		if(authinfo->authorized_for_all_service_commands==TRUE)
			return TRUE;
	        }

	return FALSE;
        }


/* check is the current user is authorized to issue commands relating to a particular host */
int is_authorized_for_host_commands(host *hst, authdata *authinfo){
	contact *temp_contact;

	if(hst==NULL)
		return FALSE;

	/* if we're not using authentication, fake it */
	if(use_authentication==FALSE)
		return TRUE;

	/* if this user has not authenticated return error */
	if(authinfo->authenticated==FALSE)
		return FALSE;

	/* the user is authorized if they have rights to the host */
	if(is_authorized_for_host(hst,authinfo)==TRUE){

		/* find the contact */
		temp_contact=find_contact(authinfo->username);

		/* reject if contact is not allowed to issue commands */
		if(temp_contact && temp_contact->can_submit_commands==FALSE)
			return FALSE;

		/* this user is a contact for the host, so they have permission... */
		if(is_contact_for_host(hst,temp_contact)==TRUE)
			return TRUE;

		/* this user is an escalated contact for the host, so they have permission... */
		if(is_escalated_contact_for_host(hst,temp_contact)==TRUE)
			return TRUE;

		/* this user is not a contact for the host, so they must have been given explicit permissions to all host commands */
		if(authinfo->authorized_for_all_host_commands==TRUE)
			return TRUE;
	        }

	return FALSE;
        }


