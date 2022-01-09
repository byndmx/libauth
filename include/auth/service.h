#ifndef _BYND_AUTH_SERVICE_H_
#define _BYND_AUTH_SERVICE_H_

#include "auth/config.h"

#define AUTH_SERVICE_NAME_SIZE				128
#define AUTH_SERVICE_ADDRESS_SIZE			128

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthService {

	unsigned int service_name_len;
	char service_name[AUTH_SERVICE_NAME_SIZE];

	unsigned int auth_service_address_len;
	char auth_service_address[AUTH_SERVICE_ADDRESS_SIZE];

} AuthService;

AUTH_PRIVATE AuthService *auth_service_new (void);

AUTH_PUBLIC void auth_service_delete (void *auth_service_ptr);

AUTH_EXPORT AuthService *auth_service_create (
	const char *service_name,
	const char *auth_service_address
);

#ifdef __cplusplus
}
#endif

#endif