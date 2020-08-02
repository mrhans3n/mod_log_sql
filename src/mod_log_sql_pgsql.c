/* $Id:mod_log_sql_pgsql.c 180 2008-09-21 15:54:12Z urkle@drip.ws $ */

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

#include "libpq-fe.h"

/* Connect to the PostgreSQL database */
static logsql_opendb_ret log_sql_pgsql_connect(server_rec * s, logsql_dbconnection * db)
{
    if(db->handle != NULL)
	PQreset(db->handle);
    else {
	apr_uri_t *uri = apr_palloc(s->process->pool, sizeof(apr_uri_t));

	uri->scheme =   (char *) apr_table_get(db->parms, "driver");
	uri->hostname = (char *) apr_table_get(db->parms, "hostname");
	uri->user =     (char *) apr_table_get(db->parms, "username");
	uri->password = (char *) apr_table_get(db->parms, "password");
	uri->port_str = (char *) apr_table_get(db->parms, "port");
	uri->path =     (char *) apr_pstrcat(s->process->pool, "/", apr_table_get(db->parms, "database"), NULL);

	char *dburi = apr_uri_unparse(s->process->pool, uri, APR_URI_UNP_REVEALPASSWORD);

	db->handle = PQconnectdb(dburi);
    }

    if(PQstatus(db->handle) == CONNECTION_OK) {
	PQexec(db->handle, "SET TIMEZONE TO GMT;");
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "log_sql_pgsql_connect: Time Zone set to GMT");
    }

    if (PQstatus(db->handle) == CONNECTION_OK) {
	db->connected = 1;
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "log_sql_pgsql_connect: database connection success");
	return LOGSQL_OPENDB_SUCCESS;
    } else if (db->handle) {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "log_sql_pgsql_connect: database connection error: %s", PQerrorMessage(db->handle));
	db->connected = 0;
	return LOGSQL_OPENDB_FAIL;
    } else {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "log_sql_pgsql_connect: database connection error: no handle");
	db->connected = 0;
	return LOGSQL_OPENDB_FAIL;
    }
}

/* Close the DB link */
static void log_sql_pgsql_close(logsql_dbconnection * db)
{
    PQfinish(db->handle);
    db->handle = NULL;
    db->connected = 0;
    log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "log_sql_pgsql_close: database connection closed");
}

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 * Also PQescapeString does not place the ' around the string. So we have
 * to do this manually
 */
static const char *log_sql_pgsql_escape(request_rec * r, const char *from_str, apr_pool_t * p, logsql_dbconnection * db)
{
    if (from_str) {

	apr_size_t size = strlen(from_str);
	char esc_str[size * 2];

	if (db->connected && db->handle && PQstatus(db->handle) == CONNECTION_OK) {
	    /* PostgreSQL is available, so I'll go ahead and respect the current charset when
	     * I perform the escape.
	     */
	    PQescapeStringConn(db->handle, esc_str, from_str, size, NULL);
	} else {
	    /* Well, I would have liked to use the current database charset. PostgreSQL is
	     * unavailable, however, so I fall back to the slightly less respectful
	     * PQescapeString() function that uses the default charset.
	     */
	    PQescapeString(esc_str, from_str, size);
	}

	return apr_pstrcat(r->pool, "'", esc_str, "'", NULL);
    }

    return NULL;
}

/* Run a sql insert query and return a categorized error or success */
static logsql_query_ret log_sql_pgsql_query(request_rec * r, logsql_dbconnection * db, const char *query)
{
    PGresult *result;
    const char *real_error_str = NULL;

    /* Run the query */
    result = PQexec(db->handle, query);
    if (PQresultStatus(result) == PGRES_COMMAND_OK) {
	PQclear(result);
	return LOGSQL_QUERY_SUCCESS;
    }

    real_error_str = PQresultErrorMessage(result);
    if (strstr(real_error_str, "ERROR:  relation \"") && strstr(real_error_str, "\" does not exist")) {
	PQclear(result);
	return LOGSQL_QUERY_NOTABLE;
    }

    /* Query failed, reopen connection if broken, and retry query */
    if (PQstatus(db->handle) != CONNECTION_OK) {
	PQreset(db->handle);
	PQexec(db->handle, "SET TIMEZONE TO GMT;");

	/* Re-Run the query */
	result = PQexec(db->handle, query);
	if (PQresultStatus(result) == PGRES_COMMAND_OK) {
	    PQclear(result);
	    return LOGSQL_QUERY_SUCCESS;
	}
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_sql_pgsql_query: reconnect attempted but query failed");

	if (PQstatus(db->handle) != CONNECTION_OK) {
	    PQclear(result);
	    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_sql_pgsql_query: didn't reconnect");
	    return LOGSQL_QUERY_NOLINK;
	}

	real_error_str = PQresultErrorMessage(result);
	if (strstr(real_error_str, "ERROR:  relation \"") && strstr(real_error_str, "\" does not exist")) {
	    PQclear(result);
	    return LOGSQL_QUERY_NOTABLE;
	}
    }

    PQclear(result);
    return LOGSQL_QUERY_FAIL;
}

/* Create table table_name of type table_type. */
static logsql_table_ret log_sql_pgsql_create(request_rec * r, logsql_dbconnection * db,
					     logsql_tabletype table_type, const char *table_name)
{

    char *create_prefix = "create table if not exists ";
    char *create_suffix = NULL;
    char *create_sql;

    if (!db->createtables) {
	return LOGSQL_TABLE_SUCCESS;
    }

    if (PQstatus(db->handle) != CONNECTION_OK) {
	return LOGSQL_TABLE_FAIL;
    }

    switch (table_type) {
    case LOGSQL_TABLE_ACCESS:
	create_suffix = "(\
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
                local_address inet                      ,\
                server_name character varying(255)      ,\
                remote_address inet                     ,\
                remote_host character varying(50)       ,\
                remote_logname character varying(50)    ,\
                remote_user character varying(50)       ,\
                request_duration integer                ,\
                request_line character varying(255)     ,\
                request_method character varying(16)    ,\
                request_protocol character varying(10)  ,\
                request_time timestamp with time zone	,\
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
	create_suffix = " (\
		id character(28) not null		,\
		item character varying(80)		,\
		val character varying(255)		 \
	    )";
	break;
    }

    /* Find memory long enough to hold the whole CREATE string + \0 */
    create_sql = apr_pstrcat(r->pool, create_prefix, table_name, create_suffix, NULL);

    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "create string: %s", create_sql);

    /* Run the create query */
    if (log_sql_pgsql_query(r, db, create_sql) != LOGSQL_QUERY_SUCCESS) {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "failed to create table: %s", table_name);
	return LOGSQL_TABLE_FAIL;
    }

    return LOGSQL_TABLE_SUCCESS;
}

static const char *supported_drivers[] = { "postgres", NULL };

static logsql_dbdriver pgsql_driver = {
    "postgres",
    supported_drivers,
    log_sql_pgsql_connect,	/* open DB connection */
    log_sql_pgsql_close,	/* close DB connection */
    log_sql_pgsql_escape,	/* escape query */
    log_sql_pgsql_query,	/* insert query */
    log_sql_pgsql_create	/* create table */
};

LOGSQL_REGISTER(pgsql)
{
    log_sql_register_driver(p, &pgsql_driver);
    LOGSQL_REGISTER_RETURN;
}
