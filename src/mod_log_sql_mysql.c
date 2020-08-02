/* $Id:mod_log_sql_mysql.c 180 2008-09-21 15:54:12Z urkle@drip.ws $ */

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

#include "mysql.h"
#include "mysqld_error.h"

#include <stdbool.h>

/* Connect to the MYSQL database */
static logsql_opendb_ret log_sql_mysql_connect(server_rec * s, logsql_dbconnection * db)
{
    const char *host = apr_table_get(db->parms, "hostname");
    const char *user = apr_table_get(db->parms, "username");
    const char *passwd = apr_table_get(db->parms, "password");
    const char *database = apr_table_get(db->parms, "database");
    const char *s_tcpport = apr_table_get(db->parms, "port");
    unsigned int tcpport = (s_tcpport) ? atoi(s_tcpport) : 3306;
    const char *socketfile = apr_table_get(db->parms, "socketfile");

    if (!socketfile) {
        socketfile = "/var/lib/mysql/mysql.sock";
    }

    if(db->handle == NULL) {
	db->handle = mysql_init(NULL);

        bool reconnect = true;
        char *set_timezone = "SET TIME_ZONE = 'GMT';";

        mysql_options(db->handle, MYSQL_OPT_RECONNECT, &reconnect);
        mysql_options(db->handle, MYSQL_INIT_COMMAND, set_timezone);
    }

    if (mysql_real_connect(db->handle, host, user, passwd, database, tcpport, socketfile, 0)) {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
		  host, tcpport, database, user, socketfile);
	db->connected = 1;

	int mysql_server_version_major = (int) (mysql_get_server_version(db->handle) / 10000);
	int mysql_client_version_major = (int) (mysql_get_client_version() / 10000);

	if(mysql_server_version_major != mysql_client_version_major)
	    log_error(APLOG_MARK, APLOG_WARNING, 0, s,
		"client/server version mismatch (%i/%i), use mariadb-connector with mariadb, mysql-connector with mysql",
		mysql_server_version_major,
		mysql_client_version_major
	    );

	return LOGSQL_OPENDB_SUCCESS;
    } else {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_log_sql_mysql: database connection error: mysql error: %s",
		  mysql_error(db->handle));
	log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
		  host, tcpport, database, user, socketfile);
	db->connected = 0;
	return LOGSQL_OPENDB_FAIL;
    }
}

/* Close the DB link */
static void log_sql_mysql_close(logsql_dbconnection * db)
{
    mysql_close((MYSQL *) db->handle);
    /* mysql_close frees this data so NULL it out incase we reconnect later */
    db->handle = NULL;
    db->connected = 0;
}

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
static const char *log_sql_mysql_escape(request_rec * r, const char *from_str, apr_pool_t * p, logsql_dbconnection * db)
{
    if (from_str) {

	apr_size_t size = strlen(from_str);
        char esc_str[size * 2];

	if (db->connected && db->handle && mysql_ping(db->handle) == 0) {
	    /* MySQL is available, so I'll go ahead and respect the current charset when
	     * I perform the escape.
	     */
	    mysql_real_escape_string(db->handle, esc_str, from_str, size);
	} else {
	    /* Well, I would have liked to use the current database charset.  mysql is
	     * unavailable, however, so I fall back to the slightly less respectful
	     * mysql_escape_string() function that uses the default charset.
	     */
	    mysql_escape_string(esc_str, from_str, size);
	}

        return apr_pstrcat(r->pool, "'", esc_str, "'", NULL);
    }

    return NULL;
}

#if defined(WIN32)
#define SIGNAL_GRAB
#define SIGNAL_RELEASE
#define SIGNAL_VAR
#else
#define SIGNAL_VAR void (*handler) (int);
#define SIGNAL_GRAB handler = signal(SIGPIPE, SIG_IGN);
#define SIGNAL_RELEASE signal(SIGPIPE, handler);
#endif
/* Run a mysql insert query and return a categorized error or success */
static logsql_query_ret log_sql_mysql_query(request_rec * r, logsql_dbconnection * db, const char *query)
{
    int retval;
    const char *real_error_str;
    SIGNAL_VAR unsigned int real_error = 0;

    /* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
    SIGNAL_GRAB

    if (!db->handle || mysql_ping(db->handle))
	return LOGSQL_QUERY_NOLINK;

    /* Run the query */
    if (!(retval = mysql_query(db->handle, query))) {
	SIGNAL_RELEASE return LOGSQL_QUERY_SUCCESS;
    } else if(!mysql_ping(db->handle)) {
	if (!(retval = mysql_query(db->handle, query))) {
    	    SIGNAL_RELEASE return LOGSQL_QUERY_SUCCESS;
	}
    }

    real_error = mysql_errno(db->handle);
    real_error_str = mysql_error(db->handle);
    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mysql_query returned (%d): %s", real_error, real_error_str);

    /* Check to see if the error is "nonexistent table" */
    if (real_error == ER_NO_SUCH_TABLE) {
	/* Restore SIGPIPE to its original handler function */
	SIGNAL_RELEASE return LOGSQL_QUERY_NOTABLE;
    }

    /* Restore SIGPIPE to its original handler function */
    SIGNAL_RELEASE return LOGSQL_QUERY_FAIL;
}

/* Create table table_name of type table_type. */
static logsql_table_ret log_sql_mysql_create(request_rec * r, logsql_dbconnection * db,
					     logsql_tabletype table_type, const char *table_name)
{
    int retval;
    const char *tabletype = apr_table_get(db->parms, "tabletype");
    SIGNAL_VAR char *type_suffix = NULL;

    char *create_prefix = "create table if not exists `";
    char *create_suffix = NULL;
    char *create_sql;

    if (!db->handle) {
	return LOGSQL_TABLE_FAIL;
    }

    if (!db->createtables) {
	return LOGSQL_TABLE_FAIL;
    }

    switch (table_type) {
    case LOGSQL_TABLE_ACCESS:
	create_suffix = "` (\
        	id character(28) null unique		,\
        	service character varying(12) not null default 'APACHE',\
        	agent character varying(255)		,\
    	        bytes_sent integer			,\
    	    						"
#ifdef WITH_LOGIO_MOD
	    "\
    	        bytes_recvd integer			,\
    	    						"
#endif
	    "\
        	child_pid integer			,\
    	        child_tid bigint			,\
    	        cookie character varying(255)		,\
    	        machine_id character varying(25)	,\
    	        request_file character varying(255)	,\
    	        referer character varying(255)		,\
    	        local_address character(15)		,\
    	        server_name character varying(255)	,\
    	        remote_address character(15)		,\
    	        remote_host character varying(50)	,\
    	        remote_logname character varying(50)	,\
    	        remote_user character varying(50)	,\
    	        request_duration integer		,\
    	        request_line character varying(255)	,\
    	        request_method character varying(16)	,\
    	        request_protocol character varying(10)	,\
        	request_time timestamp			,\
        	request_uri character varying(255)	,\
        	request_args character varying(255)	,\
        	server_port integer			,\
        	status integer				,\
        	request_timestamp integer		,\
        	virtual_host character varying(255)	,\
    		connection_status character(1)		,\
        	win32status integer			 \
        						"
#ifdef WITH_SSL_MOD
	    ",\
        	ssl_cipher character varying(25)	,\
        	ssl_keysize integer			,\
        	ssl_maxkeysize integer			"
#endif
	    ")";
	break;
    case LOGSQL_TABLE_COOKIES:
    case LOGSQL_TABLE_HEADERSIN:
    case LOGSQL_TABLE_HEADERSOUT:
    case LOGSQL_TABLE_NOTES:
	create_suffix = "` (\
		id character(28) not null 		,\
		item character varying(80)		,\
		val character varying(255)		 \
	    )";
	break;
    }

    if (tabletype) {
	type_suffix = apr_pstrcat(r->pool, " TYPE=", tabletype, NULL);
    }
    /* Find memory long enough to hold the whole CREATE string + \0 */
    create_sql = apr_pstrcat(r->pool, create_prefix, table_name, create_suffix, type_suffix, NULL);

    log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "create string: %s", create_sql);

    /* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
    SIGNAL_GRAB
	/* Run the create query */
	if ((retval = mysql_query(db->handle, create_sql))) {
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "failed to create table: %s", table_name);
	SIGNAL_RELEASE return LOGSQL_TABLE_FAIL;
    }
    SIGNAL_RELEASE return LOGSQL_TABLE_SUCCESS;
}

static const char *supported_drivers[] = { "mysql", NULL };

static logsql_dbdriver mysql_driver = {
    "mysql",
    supported_drivers,
    log_sql_mysql_connect,	/* open DB connection */
    log_sql_mysql_close,	/* close DB connection */
    log_sql_mysql_escape,	/* escape query */
    log_sql_mysql_query,	/* insert query */
    log_sql_mysql_create	/* create table */
};

LOGSQL_REGISTER(mysql)
{
    log_sql_register_driver(p, &mysql_driver);
    LOGSQL_REGISTER_RETURN;
}
