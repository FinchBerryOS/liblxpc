#ifndef LXPC_H
#define LXPC_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Aktive Verbindung zwischen zwei Prozessen.
 *
 * [3] shutdown_flag: Arc<AtomicBool> wird in Drop() gesetzt.
 *     Der Lese-Thread prüft dieses Flag nach jedem Timeout-Zyklus.
 */
typedef struct LxpcConnection LxpcConnection;

typedef struct LxpcObject LxpcObject;

typedef LxpcObject lxpc_object;

typedef LxpcConnection lxpc_connection;

void lxpc_object_release(lxpc_object *ptr);

void lxpc_string_release(char *ptr);

void lxpc_connection_release(lxpc_connection *ptr);

lxpc_object *lxpc_dictionary_create(void);

void lxpc_dictionary_set_string(lxpc_object *obj, const char *key, const char *value);

/**
 * Rückgabe MUSS mit lxpc_string_release() freigegeben werden. NULL = Key fehlt.
 */
char *lxpc_dictionary_get_string(const lxpc_object *obj, const char *key);

void lxpc_dictionary_set_int64(lxpc_object *obj, const char *key, int64_t value);

bool lxpc_dictionary_get_int64(const lxpc_object *obj, const char *key, int64_t *out);

void lxpc_dictionary_set_double(lxpc_object *obj, const char *key, double value);

bool lxpc_dictionary_get_double(const lxpc_object *obj, const char *key, double *out);

void lxpc_dictionary_set_bool(lxpc_object *obj, const char *key, bool value);

bool lxpc_dictionary_get_bool(const lxpc_object *obj, const char *key, bool *out);

void lxpc_dictionary_set_data(lxpc_object *obj, const char *key, const uint8_t *data, size_t len);

bool lxpc_dictionary_set_uuid(lxpc_object *obj, const char *key, const uint8_t *uuid_ptr);

void lxpc_dictionary_set_null(lxpc_object *obj, const char *key);

void lxpc_dictionary_set_fd(lxpc_object *obj, const char *key, int fd);

int lxpc_dictionary_get_fd(const lxpc_object *obj, const char *key);

int64_t lxpc_object_get_msg_id(const lxpc_object *obj);

int64_t lxpc_object_get_reply_to(const lxpc_object *obj);

lxpc_connection *lxpc_connection_create(const char *name);

pid_t lxpc_connection_get_peer_pid(const lxpc_connection *conn);

uid_t lxpc_connection_get_peer_uid(const lxpc_connection *conn);

gid_t lxpc_connection_get_peer_gid(const lxpc_connection *conn);

int lxpc_connection_send_message(lxpc_connection *conn, const lxpc_object *obj);

int lxpc_connection_send_reply(lxpc_connection *conn, lxpc_object *reply, int64_t reply_to_msg_id);

void lxpc_connection_resume(lxpc_connection *conn);

/**
 * WICHTIG: Handler MUSS lxpc_object_release() auf dem übergebenen Pointer aufrufen.
 */
void lxpc_connection_set_event_handler(lxpc_connection *conn, void (*handler)(lxpc_object*));

void lxpc_connection_set_error_handler(lxpc_connection *conn, void (*handler)(int, const char*));

int lxpc_bootstrap_connection_activate(void);

void lxpc_main(void (*handler)(lxpc_connection*), void (*event_handler)(lxpc_object*));

#endif  /* LXPC_H */
