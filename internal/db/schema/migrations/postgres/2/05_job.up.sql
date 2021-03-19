begin;

create table job (
    id text primary key,
    name wt_name not null,
    description wt_description not null,
    code text not null
        constraint job_code_must_be_not_empty
            check(length(trim(code)) > 0),
    next_scheduled_run timestamp with time zone not null
        default current_timestamp,

    constraint job_name_code_uq
        unique(name, code)
);

comment on table job is
    'job is a base table where each row represents a unique job that can only have one running instance at any specific time.';

create table job_name_enm (
    name text not null primary key
);

comment on table job_name_enm is
    'job_name_enm is an enumeration table where each row contains the name of a valid job.';

create table job_run (
     id serial primary key,
     job_id text not null
         constraint job_fk
             references job(id)
             on delete cascade
             on update cascade,
     server_id text
         constraint server_fk
             references server(private_id)
             on delete set null
             on update cascade,
     start_time timestamp with time zone not null
         default current_timestamp,
     end_time timestamp with time zone,
     last_heartbeat timestamp with time zone not null
         default current_timestamp,
     completed_count int not null,
     total_count int not null
         constraint job_run_total_count_greater_than_zero
            check(total_count > 0),
     status text not null
         constraint job_status_fk
             references job_run_status_enm (name)
             on delete restrict
             on update cascade,

     constraint job_run_completed_count_less_than_equal_to_total_count
         check(completed_count <= total_count)
);

comment on table job_run is
    'job_run is a table where each row represents an instance of a job run that is either actively running or has already completed.';

create unique index job_run_status_constraint
    on job_run (job_id)
    where status = 'Running' OR status = 'Scheduled';

create table job_run_status_enm (
    name text not null primary key
        constraint only_predefined_job_status_allowed
            check(name in ('running', 'complete', 'failed', 'interrupted'))
);

comment on table job_run_status_enm is
    'job_run_status_enm is an enumeration table where each row contains a valid job run state.';

insert into job_run_status_enm (name)
    values
    ('running'),
    ('complete'),
    ('failed'),
    ('interrupted');
