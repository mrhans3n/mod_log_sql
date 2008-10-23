#ifndef DATABASE_H_
#define DATABASE_H_

#include "apr_pools.h"

#include "config.h"

void database_init(apr_pool_t *p);

apr_status_t database_connect(config_t *cfg);

apr_status_t database_disconnect(config_t *cfg);

apr_status_t database_insert(config_t *cfg, apr_pool_t *p, apr_table_t *data);

#endif /*DATABASE_H_*/
