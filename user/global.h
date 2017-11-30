#include "user_interface.h"

#include "ringbuf.h"
#include "user_config.h"
#include "config_flash.h"

#include "mqtt/mqtt_server.h"
#include "mqtt/mqtt_topiclist.h"
#include "mqtt/mqtt_retainedlist.h"

#ifdef SCRIPTED
#include "lang.h"
#include "pub_list.h"
#endif

/* Hold the system wide configuration */
#define user_procTaskPrio        0

extern sysconfig_t config;
extern ringbuf_t console_rx_buffer, console_tx_buffer;
extern struct espconn *console_conn;
extern uint8_t remote_console_disconnect;
extern bool mqtt_enabled, mqtt_connected;
extern ip_addr_t my_ip;
extern ip_addr_t dns_ip;
extern bool connected;
extern uint8_t my_channel;
extern bool do_ip_config;

#ifdef MQTT_CLIENT
extern MQTT_Client mqttClient;
extern bool mqtt_enabled, mqtt_connected;
#endif

#ifdef SCRIPTED
extern uint8_t *my_script;
extern struct espconn *downloadCon;
extern struct espconn *scriptcon;

void http_script_cb(char *response_body, int http_status, char *response_headers, int body_size);
void script_connected_cb(void *arg);
#endif

void console_handle_command(struct espconn *pespconn);
void to_console(char *str);
void do_command(char *t1, char *t2, char *t3);
void con_print(uint8_t *str);
void serial_out(uint8_t *str);
