/* $Id: mod_log_sql_dbi.c 120 2004-04-17 15:14:12Z urkle@drip.ws $ */

#if defined(WITH_APACHE20)
#	include "apache20.h"
#else
#	error Unsupported Apache version
#endif


#ifdef HAVE_CONFIG_H
/* Undefine these to prevent conflicts between Apache ap_config_auto.h and 
 * my config.h. Only really needed for Apache < 2.0.48, but it can't hurt.
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "autoconfig.h"
#endif

#include "mod_log_sql.h"

#include "dbi/dbi.h"

typedef struct {
    dbi_conn conn;
} dbi_conn_rec;

static dbi_inst instance;

/* Connect to the MYSQL database */
static logsql_opendb_ret log_sql_dbi_connect(server_rec * s, logsql_dbconnection * db)
{
    const char *driver = apr_table_get(db->parms, "driver");
    const char *host = apr_table_get(db->parms, "hostname");
    const char *user = apr_table_get(db->parms, "username");
    const char *passwd = apr_table_get(db->parms, "password");
    const char *database = apr_table_get(db->parms, "database");
    const char *s_tcpport = apr_table_get(db->parms, "port");
    unsigned int tcpport = (s_tcpport) ? atoi(s_tcpport) : 0;
    const char *socketfile = apr_table_get(db->parms, "socketfile");

    //dbi_result result;
    dbi_conn_rec *dblink = db->handle;
    if (!dblink) {
	dblink = apr_pcalloc(s->process->pool, sizeof(*dblink));
	db->handle = (void *) dblink;
    }

    dblink->conn = dbi_conn_new_r(driver, &instance);

    dbi_conn_set_option(dblink->conn, "host", host);
    dbi_conn_set_option(dblink->conn, "username", user);
    dbi_conn_set_option(dblink->conn, "password", passwd);
    dbi_conn_set_option(dblink->conn, "dbname", database);
    if (tcpport) {
	dbi_conn_set_option_numeric(dblink->conn, "port", tcpport);
    }

    if (socketfile && !strcmp(driver, "mysql")) {
	dbi_conn_set_option(dblink->conn, "mysql_unix_socket", socketfile);
    }

    if (!dbi_conn_connect(dblink->conn)) {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
		  "HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'", host, tcpport, database, user, socketfile);
	db->connected = 1;
	return LOGSQL_OPENDB_SUCCESS;
    } else {
	const char *error;
	dbi_conn_error(dblink->conn, &error);
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "DBI Error: %s", error);
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
		  "HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'", host, tcpport, database, user, socketfile);
	db->connected = 0;
	return LOGSQL_OPENDB_FAIL;
    }
}

/* Close the DB link */
static void log_sql_dbi_close(logsql_dbconnection * db)
{
    dbi_conn_rec *dblink = db->handle;
    dbi_conn_close(dblink->conn);
    dblink->conn = NULL;
    db->connected = 0;
}

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
static const char *log_sql_dbi_escape(request_rec * r, const char *from_str, apr_pool_t * p, logsql_dbconnection * db)
{
    dbi_conn_rec *dblink = db->handle;

    if (from_str) {
	char *to_str = strdup(from_str);
	char *retval;
	dbi_conn_quote_string(dblink->conn, &to_str);
	retval = apr_pstrdup(p, to_str);
	free(to_str);

	return retval;
    }

    return NULL;
}

/* Run a mysql insert query and return a categorized error or success */
static logsql_query_ret log_sql_dbi_query(request_rec * r, logsql_dbconnection * db, const char *query)
{
    const char *error;
    dbi_result result;
    dbi_conn_rec *dblink = db->handle;

    if (!dblink->conn) {
	return LOGSQL_QUERY_NOLINK;
    }

    /* Run the query */
    if ((result = dbi_conn_query(dblink->conn, query))) {
	return LOGSQL_QUERY_SUCCESS;
    }
    /* Check to see if the error is "nonexistent table" */
    dbi_conn_error(dblink->conn, &error);
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DBI Error: %s", error);
/*	if (real_error == ER_NO_SUCH_TABLE) {
		log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"table does not exist, preserving query");
		return LOGSQL_QUERY_NOTABLE;
	}*/
    return LOGSQL_QUERY_FAIL;
}

/* Create table table_name of type table_type. */
static logsql_table_ret log_sql_dbi_create(request_rec * r, logsql_dbconnection * db,
					   logsql_tabletype table_type, const char *table_name)
{
    dbi_result result;
    const char *driver = apr_table_get(db->parms, "driver");
    const char *tabletype = apr_table_get(db->parms, "tabletype");
    char *type_suffix = NULL;

    char *create_prefix = "create table if not exists `";
    char *create_suffix = NULL;
    char *create_sql;

    dbi_conn_rec *dblink = db->handle;

    if (!db->createtables) {
	return APR_SUCCESS;
    }

    switch (table_type) {
    case LOGSQL_TABLE_ACCESS:
	create_suffix = "` (\
                id character(28) null unique            ,\
                service character varying(12) not null default 'APACHE',\
                agent character varying(255)            ,\
                bytes_sent integer                      ,\
                                                        "
#ifdef WITH_LOGIO_MOD
	    "\
                bytes_recvd integer                     ,\
                                                        "
#endif
	    "\
                child_pid integer                       ,\
                child_tid bigint                        ,\
                cookie character varying(255)           ,\
                machine_id character varying(25)        ,\
                request_file character varying(255)     ,\
                referer character varying(255)          ,\
                local_address varchar(16)               ,\
                server_name character varying(255)      ,\
                remote_address varchar(16)              ,\
                remote_host character varying(50)       ,\
                remote_logname character varying(50)    ,\
                remote_user character varying(50)       ,\
                request_duration integer                ,\
                request_line character varying(255)     ,\
                request_method character varying(16)    ,\
                request_protocol character varying(10)  ,\
                request_time character(27)		,\
                request_uri character varying(255)      ,\
                request_args character varying(255)     ,\
                server_port integer                     ,\
                status integer                          ,\
                request_timestamp integer               ,\
                virtual_host character varying(255)     ,\
                connection_status character(1)          ,\
                win32status integer                      \
                                                        "
#ifdef WITH_SSL_MOD
	    ",\
                ssl_cipher character varying(25)        ,\
                ssl_keysize integer                     ,\
                ssl_maxkeysize integer                  "
#endif
	    ")";
	break;
    case LOGSQL_TABLE_COOKIES:
    case LOGSQL_TABLE_HEADERSIN:
    case LOGSQL_TABLE_HEADERSOUT:
    case LOGSQL_TABLE_NOTES:
	create_suffix = "` (\
		id character(28) not null		,\
		item character varying(80)		,\
		val character varying(255)		 \
	    )";
	break;
    }

    if (tabletype && !strcmp(driver, "mysql")) {
	type_suffix = apr_pstrcat(r->pool, " TYPE=", tabletype, NULL);
    }
    /* Find memory long enough to hold the whole CREATE string + \0 */
    create_sql = apr_pstrcat(r->pool, create_prefix, table_name, create_suffix, type_suffix, NULL);

    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "create string: %s", create_sql);

    if (!dblink) {
	return LOGSQL_QUERY_NOLINK;
    }

    /* Run the create query */
    if (!(result = dbi_conn_query(dblink, create_sql))) {
	const char *error;
	dbi_conn_error(dblink->conn, &error);
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DBI Error: %s", error);
	return LOGSQL_TABLE_FAIL;
    }

    return LOGSQL_TABLE_SUCCESS;
}

static logsql_dbdriver log_sql_dbi_driver = {
    "dbi",
    NULL,
    log_sql_dbi_connect,	/* open DB connection */
    log_sql_dbi_close,		/* close DB connection */
    log_sql_dbi_escape,		/* escape query */
    log_sql_dbi_query,		/* insert query */
    log_sql_dbi_create		/* create table */
};

static apr_status_t log_sql_dbi_cleanup(void *data)
{
    dbi_shutdown_r(instance);
    return APR_SUCCESS;
}

LOGSQL_REGISTER(dbi)
{
    dbi_driver driver;
    const char **driver_list;
    int count = 1;

    dbi_initialize_r(NULL, &instance);

    for (driver = dbi_driver_list_r(NULL, instance); driver; driver = dbi_driver_list_r(driver, instance)) {
	count++;
    }
    driver_list = apr_pcalloc(p, sizeof(char *) * (count));
    count = 0;
    for (driver = dbi_driver_list_r(NULL, instance); driver; driver = dbi_driver_list_r(driver, instance)) {
	driver_list[count++] = dbi_driver_get_name(driver);
    }
    log_sql_dbi_driver.provided_drivers = driver_list;
    log_sql_register_driver(p, &log_sql_dbi_driver);
    apr_pool_pre_cleanup_register(p, NULL, log_sql_dbi_cleanup);
    LOGSQL_REGISTER_RETURN;
}
