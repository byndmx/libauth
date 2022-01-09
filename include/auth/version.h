#ifndef _BYND_AUTH_VERSION_H_
#define _BYND_AUTH_VERSION_H_

#define BYND_AUTH_VERSION			"0.1.1"
#define BYND_AUTH_VERSION_NAME		"Version 0.1.1"
#define BYND_AUTH_VERSION_DATE		"09/01/2022"
#define BYND_AUTH_VERSION_TIME		"11:02 CST"
#define BYND_AUTH_VERSION_AUTHOR	"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

// print full bynd libauth version information
extern void bynd_libauth_version_print_full (void);

// print the version id
extern void bynd_libauth_version_print_version_id (void);

// print the version name
extern void bynd_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif