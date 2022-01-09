#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include <cerver/http/http.h>
#include <cerver/http/request.h>

#include <cerver/http/json/json.h>

#ifdef BYND_DEBUG
#include <cerver/utils/log.h>
#endif

#include "auth/auth.h"
#include "auth/permissions.h"
#include "auth/requests.h"
#include "auth/service.h"

const char *bynd_auth_type_to_string (const ByndAuthType type) {

	switch (type) {
		#define XX(num, name, string) case BYND_AUTH_TYPE_##name: return #string;
		BYND_AUTH_TYPE_MAP(XX)
		#undef XX
	}

	return bynd_auth_type_to_string (BYND_AUTH_TYPE_NONE);

}

static ByndAuth *bynd_auth_new (void) {

	ByndAuth *auth = (ByndAuth *) malloc (sizeof (ByndAuth));
	if (auth) {
		(void) memset (auth, 0, sizeof (ByndAuth));

		auth->type = BYND_AUTH_TYPE_NONE;

		auth->permissions = NULL;
	}

	return auth;

}

void bynd_auth_delete (void *auth_ptr) {

	if (auth_ptr) {
		ByndAuth *bynd_auth = (ByndAuth *) auth_ptr;

		dlist_delete (bynd_auth->permissions);

		free (auth_ptr);
	}

}

const ByndAuthType bynd_auth_get_type (const ByndAuth *bynd_auth) {

	return bynd_auth->type;

}

const char *bynd_auth_get_competition (const ByndAuth *bynd_auth) {

	return bynd_auth->competition;

}

const char *bynd_auth_get_action (const ByndAuth *bynd_auth) {

	return bynd_auth->action;

}

const bool bynd_auth_get_admin (const ByndAuth *bynd_auth) {

	return bynd_auth->super_admin;

}

static void bynd_auth_set_admin (ByndAuth *bynd_auth, const bool is_admin) {

	bynd_auth->super_admin = is_admin;

}

DoubleList *bynd_auth_get_permissions (ByndAuth *bynd_auth) {

	return bynd_auth->permissions;

}

bool bynd_auth_permissions_iter_start (ByndAuth *bynd_auth) {

	bool retval = false;

	if (bynd_auth) {
		if (bynd_auth->permissions) {
			if (dlist_start (bynd_auth->permissions)) {
				bynd_auth->next_permissions = dlist_start (
					bynd_auth->permissions
				);

				retval = true;
			}
		}
	}

	return retval;

}

const Permissions *bynd_auth_permissions_iter_get_next (
	ByndAuth *bynd_auth
) {

	const Permissions *permissions = NULL;

	if (bynd_auth->next_permissions) {
		permissions = (const Permissions *) bynd_auth->next_permissions->data;
		bynd_auth->next_permissions = bynd_auth->next_permissions->next;
	}

	return permissions;

}

ByndAuth *bynd_auth_create (const ByndAuthType type) {

	ByndAuth *bynd_auth = bynd_auth_new ();
	if (bynd_auth) {
		bynd_auth->type = type;

		switch (bynd_auth->type) {
			case BYND_AUTH_TYPE_NONE: break;

			case BYND_AUTH_TYPE_SINGLE: break;

			case BYND_AUTH_TYPE_MANAGEMENT:
				bynd_auth->permissions = dlist_init (permissions_delete, NULL);
				break;

			default: break;
		}
	}

	return bynd_auth;

}

static void bynd_single_authentication_internal (
	const HttpRequest *request,
	const char *competition, const char *action
) {

	#ifdef BYND_DEBUG
	cerver_log_success ("Success auth!");
	#endif

	ByndAuth *bynd_auth = bynd_auth_create (BYND_AUTH_TYPE_SINGLE);

	(void) strncpy (bynd_auth->competition, competition, AUTH_COMPETITION_SIZE - 1);
	(void) strncpy (bynd_auth->action, action, AUTH_ACTION_SIZE - 1);

	http_request_set_custom_data (
		(HttpRequest *) request, bynd_auth
	);

	http_request_set_delete_custom_data (
		(HttpRequest *) request, bynd_auth_delete
	);

}

unsigned int bynd_single_authentication (
	const HttpReceive *http_receive, const HttpRequest *request,
	const char *competition, const char *action
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_cerver_get_custom_data (
			http_receive->http_cerver
		);

		AuthRequest auth_request = { 0 };
		auth_request_create_single (
			&auth_request, token->str,
			competition, action	
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address,
			&auth_request
		)) {
			bynd_single_authentication_internal (
				request,
				competition, action
			);

			retval = 0;
		}
	}

	#ifdef BYND_DEBUG
	else {
		cerver_log_error (
			"bynd_single_authentication () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}

static inline void bynd_management_authentication_parse_single_competition (
	Permissions *permissions, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_object) == JSON_OBJECT) {
		json_object_foreach (json_object, key, value) {
			if (!strcmp (key, "_id")) {
				(void) strncpy (
					permissions->competition,
					json_string_value (value),
					AUTH_COMPETITION_SIZE - 1
				);
			}

			else if (!strcmp (key, "actions")) {
				size_t n_actions = json_array_size (value);
				for (size_t i = 0; i < n_actions; i++) {
					(void) dlist_insert_after_unsafe (
						permissions->actions,
						dlist_end (permissions->actions),
						permissions_action_create (
							json_string_value (json_array_get (value, i))
						)
					);
				}
			}
		}
	}

}

static inline void bynd_management_authentication_parse_competitions (
	ByndAuth *bynd_auth, json_t *competitions_array
) {

	size_t n_competitions = json_array_size (competitions_array);
	json_t *json_object = NULL;
	for (size_t i = 0; i < n_competitions; i++) {
		json_object = json_array_get (competitions_array, i);
		if (json_object) {
			Permissions *permissions = permissions_create ();
			if (permissions) {
				bynd_management_authentication_parse_single_competition (
					permissions, json_object
				);

				(void) dlist_insert_after_unsafe (
					bynd_auth->permissions,
					dlist_end (bynd_auth->permissions),
					permissions
				);
			}
		}
	}

}

static inline void bynd_management_authentication_parse_json (
	ByndAuth *bynd_auth, json_t *json_body
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "competitions")) {
				if (json_typeof (value) == JSON_ARRAY) {
					bynd_management_authentication_parse_competitions (
						bynd_auth, value
					);
				}
			}

			else if (!strcmp (key, "admin")) {
				bynd_auth_set_admin (bynd_auth, json_boolean_value (value));
			}
		}
	}

}

static unsigned int bynd_management_authentication_handle_response (
	ByndAuth *bynd_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		bynd_management_authentication_parse_json (bynd_auth, json_body);

		json_decref (json_body);

		retval = 0;
	}

	#ifdef BYND_DEBUG
	else {
		cerver_log_error (
			"bynd_custom_auth () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

	return retval;

}

static unsigned int bynd_management_authentication_internal (
	const HttpRequest *request, AuthRequest *auth_request
) {

	unsigned int retval = 1;

	ByndAuth *bynd_auth = bynd_auth_create (BYND_AUTH_TYPE_MANAGEMENT);

	// get actions mask from response's body
	if (!bynd_management_authentication_handle_response (
		bynd_auth, auth_request->response
	)) {
		#ifdef BYND_DEBUG
		cerver_log_success ("Success auth!");
		#endif

		http_request_set_custom_data (
			(HttpRequest *) request, bynd_auth
		);

		http_request_set_delete_custom_data (
			(HttpRequest *) request, bynd_auth_delete
		);

		retval = 0;
	}

	return retval;

}

unsigned int bynd_management_authentication (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_cerver_get_custom_data (
			http_receive->http_cerver
		);

		AuthRequest auth_request = { 0 };
		auth_request_create_management (
			&auth_request, token->str
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address,
			&auth_request
		)) {
			bynd_management_authentication_internal (
				request, &auth_request
			);

			retval = 0;
		}
	}

	#ifdef BYND_DEBUG
	else {
		cerver_log_error (
			"bynd_management_authentication () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}
