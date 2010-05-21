#include "../include/config.h"
#include "../include/common.h"
#include "../include/icinga.h"
#include "../include/locations.h"
#include "../include/statsprofiler.h"

extern profile_object* profiled_data;

double safe_divide(double x, int y, int reverse)
{

    double ans;
    if(x == 0 || y ==0)
    {
        ans = 0.0f;
    }else{
        if(reverse)
        {
            ans = y/x;
        }else{
            ans = x/y;
        }
    }
    return ans;
}

profile_object* profiled_data_find_last_object()
{
    profile_object* p = profiled_data;
    if(p)
    {
        while(p->next && p->next != p)
            p = p->next;
    }
    return p;
}

profile_object* profile_object_create(char * name)
{
    profile_object* new_p =  (profile_object*) calloc(1,sizeof(profile_object));
    profile_object* old_p = profiled_data_find_last_object();

    if(!old_p)
    {
        profiled_data = old_p = new_p;
    }

    if(new_p != old_p)
        old_p->next = new_p;

    new_p->name = strdup(name);
    return new_p;
}

profile_object* profile_object_find_by_name(char * name)
{
    profile_object* p = profiled_data;
    char * n_name = calloc(strlen(name)+1,sizeof(char));
    strncpy(n_name,name,strlen(name));

    while(p != NULL)
    {
        if(strcmp(n_name,p->name)==0)
        {
            break;
        }
        p = p->next;
    }

    if(!p)
    {
        p = profile_object_create(n_name);
    }
    free(n_name);
    return p;
}

void profile_object_update_count(char * name, int val)
{
    profile_object* new_p = profile_object_find_by_name(name);
    new_p->count=val;
}

void profile_object_update_elapsed(char * name, double val)
{
    profile_object * new_p = profile_object_find_by_name(name);
    new_p->elapsed=val;
}

void profile_data_print()
{
    int count,x;
    char * name;
    double elapsed;
    double total_time;
    profile_object *t, *p = profiled_data;
    t=profile_object_find_by_name("EVENT_LOOP_COMPLETION");
    total_time = t->elapsed;

    while(p)
    {
       name = p->name;
       count = p->count;
       elapsed = p->elapsed;

       printf("%s\t\t\t%.3f / %d / %.4f / %.4f\n",name,elapsed,count,safe_divide(elapsed,count,0),safe_divide(total_time,count,1));
       p = p->next;
    }
}

void profile_data_output_mrtg(char * name, char * delim)
{
    int t_len = strlen(name);
    char t_name[t_len];
    strncpy(t_name,name+strlen("COUNTER_"),t_len);
    profile_object* p = profile_object_find_by_name(t_name);
    profile_object* t = profile_object_find_by_name("EVENT_LOOP_COMPLETION");

    if(strstr(name,"ELAPSED"))
        printf("%.3f%s",p->elapsed,delim);

    if(strstr(name,"COUNTER"))
        printf("%d%s",p->count,delim);

    if(strstr(name,"EVENTPS"))
        printf("%.4f%s",safe_divide(t->elapsed,p->count,1),delim);
}
