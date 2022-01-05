#include <cerver/utils/log.h>

#include "auth/version.h"

// print full libauth version information
void bynd_libauth_version_print_full (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nBynd libauth Version: %s", BYND_AUTH_VERSION_NAME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Release Date & time: %s - %s", BYND_AUTH_VERSION_DATE, BYND_AUTH_VERSION_TIME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Author: %s\n", BYND_AUTH_VERSION_AUTHOR
	);

}

// print the version id
void bynd_libauth_version_print_version_id (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nBynd libauth Version ID: %s\n", BYND_AUTH_VERSION
	);

}

// print the version name
void bynd_libauth_version_print_version_name (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nBynd libauth Version: %s\n", BYND_AUTH_VERSION_NAME
	);

}
