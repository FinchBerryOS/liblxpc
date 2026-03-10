#ifndef LXPC_H
#define LXPC_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Repräsentiert eine aktive Verbindung zwischen zwei Prozessen.
 */
typedef struct LxpcConnection LxpcConnection;

/**
 * Das Haupt-Dictionary das als Paket zwischen Prozessen verschickt wird.
 */
typedef struct LxpcObject LxpcObject;

typedef LxpcObject lxpc_object;

typedef LxpcConnection lxpc_connection;

/**
 * Gibt ein LxpcObject frei das von LXPC auf dem Heap alloziert wurde.
 *
 * MUSS nach jedem Aufruf eines Message-Handlers genau einmal aufgerufen werden.
 * Doppelter Aufruf ist undefined behavior.
 */
void lxpc_object_release(lxpc_object *ptr);

/**
 * Gibt einen String frei der von lxpc_dictionary_get_string zurückgegeben wurde.
 *
 * MUSS für jeden von LXPC zurückgegebenen String genau einmal aufgerufen werden.
 */
void lxpc_string_release(char *ptr);

/**
 * Gibt eine LxpcConnection frei.
 *
 * Sollte erst aufgerufen werden wenn der Lese-Thread nicht mehr läuft.
 */
void lxpc_connection_release(lxpc_connection *ptr);

/**
 * Erzeugt ein neues, leeres Dictionary. Gibt NULL zurück wenn die Allokation scheitert.
 * Muss mit lxpc_object_release() freigegeben werden.
 */
lxpc_object *lxpc_dictionary_create(void);

void lxpc_dictionary_set_string(lxpc_object *obj, const char *key, const char *value);

/**
 * Gibt den Wert als neu allozierter C-String zurück.
 * MUSS mit lxpc_string_release() freigegeben werden.
 * Gibt NULL zurück wenn der Key nicht existiert oder kein String ist.
 */
char *lxpc_dictionary_get_string(const lxpc_object *obj, const char *key);

void lxpc_dictionary_set_int64(lxpc_object *obj, const char *key, int64_t value);

bool lxpc_dictionary_get_int64(const lxpc_object *obj, const char *key, int64_t *out);

void lxpc_dictionary_set_double(lxpc_object *obj, const char *key, double value);

bool lxpc_dictionary_get_double(const lxpc_object *obj, const char *key, double *out);

void lxpc_dictionary_set_bool(lxpc_object *obj, const char *key, bool value);

bool lxpc_dictionary_get_bool(const lxpc_object *obj, const char *key, bool *out);

/**
 * Setzt einen rohen Byte-Blob. Die Daten werden kopiert.
 */
void lxpc_dictionary_set_data(lxpc_object *obj, const char *key, const uint8_t *data, size_t len);

/**
 * Setzt eine UUID (genau 16 Bytes). Gibt false zurück wenn uuid_ptr NULL ist.
 */
bool lxpc_dictionary_set_uuid(lxpc_object *obj, const char *key, const uint8_t *uuid_ptr);

void lxpc_dictionary_set_null(lxpc_object *obj, const char *key);

void lxpc_dictionary_set_fd(lxpc_object *obj, const char *key, int fd);

int lxpc_dictionary_get_fd(const lxpc_object *obj, const char *key);

/**
 * Gibt die Message-ID zurück die LXPC automatisch gesetzt hat.
 * Nützlich um Antworten zuzuordnen.
 */
int64_t lxpc_object_get_msg_id(const lxpc_object *obj);

/**
 * Gibt die Reply-To-ID zurück (oder -1 wenn das kein Reply ist).
 */
int64_t lxpc_object_get_reply_to(const lxpc_object *obj);

/**
 * Verbindet sich mit einem benannten Dienst via syscored.
 * Gibt NULL zurück wenn die Verbindung fehlschlägt.
 * Muss mit lxpc_connection_release() freigegeben werden.
 */
lxpc_connection *lxpc_connection_create(const char *name);

/**
 * Sendet eine Nachricht. Gibt 0 bei Erfolg, -1 bei Fehler zurück.
 */
int lxpc_connection_send_message(lxpc_connection *conn, const lxpc_object *obj);

/**
 * Sendet eine Antwort auf eine empfangene Nachricht.
 * `reply_to_msg_id` ist der Wert von lxpc_object_get_msg_id() der Anfrage.
 */
int lxpc_connection_send_reply(lxpc_connection *conn, lxpc_object *reply, int64_t reply_to_msg_id);

/**
 * Startet den Lese-Thread. Muss vor dem Empfangen von Nachrichten aufgerufen werden.
 */
void lxpc_connection_resume(lxpc_connection *conn);

/**
 * Setzt den Handler für eingehende Nachrichten.
 * Der Handler wird aus einem Hintergrund-Thread aufgerufen.
 * WICHTIG: Der Handler MUSS lxpc_object_release() auf dem übergebenen Pointer aufrufen.
 */
void lxpc_connection_set_event_handler(lxpc_connection *conn, void (*handler)(lxpc_object*));

/**
 * Setzt den Handler für Verbindungsfehler (Verbindung getrennt, Protokollfehler, …).
 * code: Fehlercode (immer negativ), msg: lesbare Fehlerbeschreibung (UTF-8, NULL-terminiert).
 * Der String msg ist nur für die Dauer des Handler-Aufrufs gültig — nicht speichern ohne zu kopieren!
 */
void lxpc_connection_set_error_handler(lxpc_connection *conn,
                                       void (*handler)(int, const char*));

/**
 * Prüft ob der Prozess korrekt von syscored (PID 1) gestartet wurde.
 * Gibt 0 zurück bei Erfolg, negativen Fehlercode bei Misserfolg.
 */
int lxpc_bootstrap_connection_activate(void);

/**
 * Daemon-Hauptschleife. Ersetzt die normale main() in C-Daemons.
 * Blockiert bis syscored die Verbindung schließt.
 *
 * handler:       Wird für jede neue Client-Verbindung aufgerufen.
 * event_handler: Wird für Steuerbefehle von syscored aufgerufen (optional, kann NULL sein).
 */
void lxpc_main(void (*handler)(lxpc_connection*), void (*event_handler)(lxpc_object*));

#endif /* LXPC_H */
