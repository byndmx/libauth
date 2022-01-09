#ifndef _BYND_AUTH_H_
#define _BYND_AUTH_H_

#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"

#define AUTH_COMPETITION_SIZE		128
#define AUTH_ACTION_SIZE			128

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

struct _Permissions;

#define BYND_AUTH_TYPE_MAP(XX)			\
	XX(0,  NONE,      	None)			\
	XX(1,  SINGLE,      Single)			\
	XX(2,  MANAGEMENT,  Management)

typedef enum ByndAuthType {

	#define XX(num, name, string) BYND_AUTH_TYPE_##name = num,
	BYND_AUTH_TYPE_MAP(XX)
	#undef XX

} ByndAuthType;

AUTH_PUBLIC const char *bynd_auth_type_to_string (
	const ByndAuthType type
);

typedef struct ByndAuth {

	ByndAuthType type;

	char competition[AUTH_COMPETITION_SIZE];
	char action[AUTH_ACTION_SIZE];

	bool super_admin;

	DoubleList *permissions;
	ListElement *next_permissions;

} ByndAuth;

AUTH_PUBLIC void bynd_auth_delete (void *auth_ptr);

AUTH_EXPORT const ByndAuthType bynd_auth_get_type (
	const ByndAuth *bynd_auth
);

AUTH_EXPORT const char *bynd_auth_get_competition (
	const ByndAuth *bynd_auth
);

AUTH_EXPORT const char *bynd_auth_get_action (
	const ByndAuth *bynd_auth
);

AUTH_EXPORT const bool bynd_auth_get_admin (
	const ByndAuth *bynd_auth
);

AUTH_EXPORT DoubleList *bynd_auth_get_permissions (
	ByndAuth *bynd_auth
);

extern bool bynd_auth_permissions_iter_start (ByndAuth *bynd_auth);

extern const struct _Permissions *bynd_auth_permissions_iter_get_next (
	ByndAuth *bynd_auth
);

AUTH_PUBLIC ByndAuth *bynd_auth_create (const ByndAuthType type);

AUTH_EXPORT unsigned int bynd_single_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request,
	const char *competition, const char *action
);

AUTH_EXPORT unsigned int bynd_management_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif