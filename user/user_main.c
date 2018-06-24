#include "c_types.h"
#include "mem.h"
#include "ets_sys.h"
#include "osapi.h"
#include "os_type.h"
#include "sys_time.h"

#include "string.h"
#include "driver/uart.h"

#include "global.h"

#ifdef GPIO
//#include "easygpio.h"
#include "pwm.h"
#define PWM_CHANNELS 5
const uint32_t period = 5000; // * 200ns ^= 1 kHz
#endif

#ifdef NTP
#include "ntp.h"
uint64_t t_ntp_resync = 0;
#endif

#ifdef MDNS
static struct mdns_info mdnsinfo;
#endif

#ifdef DNS_RESP
#include "dns_responder.h"
#endif

#ifdef SCRIPTED
#include "lang.h"
#include "pub_list.h"

struct espconn *downloadCon;
struct espconn *scriptcon;
uint8_t *load_script;
uint32_t load_size;
#endif

/* System Task, for signals refer to user_config.h */
#define user_procTaskPrio        0
#define user_procTaskQueueLen    2
os_event_t user_procTaskQueue[user_procTaskQueueLen];
static void user_procTask(os_event_t * events);

static os_timer_t ptimer;

static int system_output;

/* Some stats */
uint64_t t_old;

/* Hold the system wide configuration */
sysconfig_t config;

ringbuf_t console_rx_buffer, console_tx_buffer;

ip_addr_t my_ip;
ip_addr_t dns_ip;
bool connected;
uint8_t my_channel;
bool do_ip_config;

void ICACHE_FLASH_ATTR user_set_softap_wifi_config(void);
void ICACHE_FLASH_ATTR user_set_softap_ip_config(void);

uint8_t remote_console_disconnect;
struct espconn *console_conn;
bool client_sent_pending;

LOCAL ICACHE_FLASH_ATTR void void_write_char(char c) {}

void ICACHE_FLASH_ATTR to_console(char *str) {
    ringbuf_memcpy_into(console_tx_buffer, str, os_strlen(str));
}

bool ICACHE_FLASH_ATTR check_connection_access(struct espconn *pesp_conn, uint8_t access_flags) {
    remot_info *premot = NULL;
    ip_addr_t *remote_addr;
    bool is_local;

    remote_addr = (ip_addr_t *)&(pesp_conn->proto.tcp->remote_ip);
    //os_printf("Remote addr is %d.%d.%d.%d\r\n", IP2STR(remote_addr));
    is_local = (remote_addr->addr & 0x00ffffff) == (config.network_addr.addr & 0x00ffffff);

    if (is_local && (access_flags & LOCAL_ACCESS))
	return true;
    if (!is_local && (access_flags & REMOTE_ACCESS))
	return true;

    return false;
}

#ifdef MQTT_CLIENT
MQTT_Client mqttClient;
bool mqtt_enabled, mqtt_connected;

static void ICACHE_FLASH_ATTR mqttConnectedCb(uint32_t * args) {
    uint8_t ip_str[16];

    MQTT_Client *client = (MQTT_Client *) args;
    mqtt_connected = true;
#ifdef SCRIPTED
    interpreter_mqtt_connect();
#endif
    os_printf("MQTT client connected\r\n");
}

static void ICACHE_FLASH_ATTR mqttDisconnectedCb(uint32_t * args) {
    MQTT_Client *client = (MQTT_Client *) args;
    mqtt_connected = false;
    os_printf("MQTT client disconnected\r\n");
}

static void ICACHE_FLASH_ATTR mqttPublishedCb(uint32_t * args) {
    MQTT_Client *client = (MQTT_Client *) args;
//  os_printf("MQTT: Published\r\n");
}

static void ICACHE_FLASH_ATTR mqttDataCb(uint32_t * args, const char *topic,
					 uint32_t topic_len, const char *data, uint32_t data_len) {
#ifdef SCRIPTED
    MQTT_Client *client = (MQTT_Client *) args;

    char *topic_copy = (char*)os_malloc(topic_len+1);
    if (topic_copy == NULL)
	return;
    os_memcpy(topic_copy, topic, topic_len);
    topic_copy[topic_len] = '\0';

    interpreter_topic_received(topic_copy, data, data_len, false);

    os_free(topic_copy);

    // Any local topics to process as result?
    pub_process();

#endif
}
#endif				/* MQTT_CLIENT */

#ifdef SCRIPTED
static void ICACHE_FLASH_ATTR script_recv_cb(void *arg, char *data, unsigned short length) {
    struct espconn *pespconn = (struct espconn *)arg;
    int index;
    uint8_t ch;

    for (index = 0; index < length; index++) {
	ch = *(data + index);
	//os_printf("%c", ch);
	if (load_size < MAX_SCRIPT_SIZE - 5)
	    load_script[4 + load_size++] = ch;
    }
}

void ICACHE_FLASH_ATTR http_script_cb(char* hostname, char* path, char *response_body, int http_status, char *response_headers, int body_size) {
    char response[64];

    if (http_status != 200) {
	os_sprintf(response, "\rHTTP script upload failed (error code %d)\r\n", http_status);
	to_console(response);
	return;
    }

    if (body_size > MAX_SCRIPT_SIZE-5) {
	os_sprintf(response, "\rHTTP script upload failed (script too long)\r\n");
	to_console(response);
	return;
    }

    char *load_script = (char *)os_malloc(body_size+5);
    if (load_script == NULL) {
	os_sprintf(response, "\rHTTP script upload failed (out of memory)\r\n");
	to_console(response);
	return;
    }
    //os_printf("LOAD: %d %x::%s\r\n", body_size, load_script, response_body);
    os_memcpy(&load_script[4], response_body, body_size);
    load_script[4 + body_size] = '\0';
    *(uint32_t *) load_script = body_size + 5;
    blob_save(SCRIPT_SLOT, (uint32_t *) load_script, body_size + 5);;
    os_free(load_script);
    blob_zero(VARS_SLOT, MAX_FLASH_SLOTS * FLASH_SLOT_LEN);

    os_sprintf(response, "\rHTTP script download completed (%d Bytes)\r\n", body_size);
    to_console(response);

    system_os_post(user_procTaskPrio, SIG_SCRIPT_HTTP_LOADED, (ETSParam) scriptcon);
}

static void ICACHE_FLASH_ATTR script_discon_cb(void *arg) {
    char response[64];

    load_script[4 + load_size] = '\0';
    *(uint32_t *) load_script = load_size + 5;
    blob_save(SCRIPT_SLOT, (uint32_t *) load_script, load_size + 5);
    os_free(load_script);
    blob_zero(VARS_SLOT, MAX_FLASH_SLOTS * FLASH_SLOT_LEN);

    os_sprintf(response, "\rScript upload completed (%d Bytes)\r\n", load_size);
    to_console(response);

    system_os_post(user_procTaskPrio, SIG_SCRIPT_LOADED, (ETSParam) scriptcon);
}

/* Called when a client connects to the script server */
void ICACHE_FLASH_ATTR script_connected_cb(void *arg) {
    char response[64];
    struct espconn *pespconn = (struct espconn *)arg;

    load_script = (uint8_t *) os_malloc(MAX_SCRIPT_SIZE);
    load_size = 0;

    //espconn_regist_sentcb(pespconn,     tcp_client_sent_cb);
    espconn_regist_disconcb(pespconn, script_discon_cb);
    espconn_regist_recvcb(pespconn, script_recv_cb);
    espconn_regist_time(pespconn, 300, 1);
}

uint32_t ICACHE_FLASH_ATTR get_script_size(void) {
    uint32_t size;

    blob_load(SCRIPT_SLOT, &size, 4);
    return size;
}

uint8_t *my_script = NULL;
uint32_t ICACHE_FLASH_ATTR read_script(void) {
    uint32_t size = get_script_size();
    if (size <= 5)
	return 0;

    my_script = (uint8_t *) os_malloc(size);

    if (my_script == 0) {
	os_printf("Out of memory");
	return 0;
    }

    blob_load(SCRIPT_SLOT, (uint32_t *) my_script, size);

    uint32_t num_token = text_into_tokens(my_script + 4);

    if (num_token == 0) {
	os_free(my_script);
	my_script = NULL;
    }
    return num_token;
}

void ICACHE_FLASH_ATTR free_script(void) {
    if (my_script != NULL) {
	free_tokens();
	os_free(my_script);
    }
    my_script = NULL;
}
#endif				/* SCRIPTED */

void ICACHE_FLASH_ATTR console_send_response(struct espconn *pespconn, bool serial_force) {
    uint16_t len = ringbuf_bytes_used(console_tx_buffer);
    char payload[len];

    if (len == 0)
	return;

    ringbuf_memcpy_from(payload, console_tx_buffer, len);
    if (pespconn != NULL) {
	if (!client_sent_pending) {
	    espconn_send(pespconn, payload, len);
	    client_sent_pending = true;
	}
    } else {
	if (system_output >= SYSTEM_OUTPUT_CMD || serial_force) {
	    UART_Send(0, payload, len);
	}
#ifdef BACKLOG
	if (backlog_buffer != NULL) {
	    char outbuf[10];
	    if (ringbuf_bytes_free(backlog_buffer) < len && !ringbuf_is_empty(backlog_buffer)) {
		ringbuf_memcpy_from(outbuf, backlog_buffer, sizeof(outbuf));
	    }
	    ringbuf_memcpy_into(backlog_buffer, payload, len);
	}
#endif
    }
}

void ICACHE_FLASH_ATTR con_print(uint8_t *str) {
    ringbuf_memcpy_into(console_tx_buffer, str, os_strlen(str));
    system_os_post(user_procTaskPrio, SIG_CONSOLE_TX_RAW, (ETSParam) console_conn);
}

void ICACHE_FLASH_ATTR serial_out(uint8_t *str) {
    UART_Send(0, str, os_strlen(str));
}

bool ICACHE_FLASH_ATTR delete_retainedtopics() {
    clear_retainedtopics();
    blob_zero(RETAINED_SLOT, MAX_RETAINED_LEN);
    return true;
}

bool ICACHE_FLASH_ATTR save_retainedtopics() {
    uint8_t buffer[MAX_RETAINED_LEN];
    int len = sizeof(buffer);
    len = serialize_retainedtopics(buffer, len);

    if (len) {
	blob_save(RETAINED_SLOT, (uint32_t *)buffer, len);
	return true;
    }
    return false;
}

bool ICACHE_FLASH_ATTR load_retainedtopics() {
    uint8_t buffer[MAX_RETAINED_LEN];
    int len = sizeof(buffer);

    blob_load(RETAINED_SLOT, (uint32_t *)buffer, len);
    return deserialize_retainedtopics(buffer, len);
}

void MQTT_local_DataCallback(uint32_t * args, const char *topic, uint32_t topic_len, const char *data, uint32_t length) {
    //os_printf("Received: \"%s\" len: %d\r\n", topic, length);
#ifdef SCRIPTED
    //interpreter_topic_received(topic, data, length, true);
    pub_insert(topic, topic_len, data, length, true);
    system_os_post(user_procTaskPrio, SIG_TOPIC_RECEIVED, 0);
#endif
}

#ifdef SCRIPTED
void ICACHE_FLASH_ATTR do_command(char *t1, char *t2, char *t3) {
    ringbuf_memcpy_into(console_rx_buffer, t1, os_strlen(t1));
    ringbuf_memcpy_into(console_rx_buffer, " ", 1);
    ringbuf_memcpy_into(console_rx_buffer, t2, os_strlen(t2));
    ringbuf_memcpy_into(console_rx_buffer, " ", 1);
    ringbuf_memcpy_into(console_rx_buffer, t3, os_strlen(t3));

    uint8_t save_locked = config.locked;
    config.locked = false;
    console_handle_command(console_conn);
    config.locked = save_locked;

    system_os_post(user_procTaskPrio, SIG_CONSOLE_TX_RAW, (ETSParam) console_conn);
}
#endif

#ifdef REMOTE_CONFIG
static void ICACHE_FLASH_ATTR tcp_client_recv_cb(void *arg, char *data, unsigned short length) {
    struct espconn *pespconn = (struct espconn *)arg;
    int index;
    uint8_t ch;

    for (index = 0; index < length; index++) {
	ch = *(data + index);
	ringbuf_memcpy_into(console_rx_buffer, &ch, 1);

	// If a complete commandline is received, then signal the main
	// task that command is available for processing
	if (ch == '\n')
	    system_os_post(user_procTaskPrio, SIG_CONSOLE_RX, (ETSParam) arg);
    }

    *(data + length) = 0;
}

static void ICACHE_FLASH_ATTR tcp_client_sent_cb(void *arg) {
    struct espconn *pespconn = (struct espconn *)arg;

    client_sent_pending = false;
    console_send_response(pespconn, false);
    
}

static void ICACHE_FLASH_ATTR tcp_client_discon_cb(void *arg) {
    os_printf("tcp_client_discon_cb(): client disconnected\n");
    struct espconn *pespconn = (struct espconn *)arg;
    console_conn = NULL;
}

/* Called when a client connects to the console server */
static void ICACHE_FLASH_ATTR tcp_client_connected_cb(void *arg) {
    char payload[128];
    struct espconn *pespconn = (struct espconn *)arg;

    os_printf("tcp_client_connected_cb(): Client connected\r\n");

    if (!check_connection_access(pespconn, config.config_access)) {
	os_printf("Client disconnected - no config access on this network\r\n");
	espconn_disconnect(pespconn);
	return;
    }

    espconn_regist_sentcb(pespconn, tcp_client_sent_cb);
    espconn_regist_disconcb(pespconn, tcp_client_discon_cb);
    espconn_regist_recvcb(pespconn, tcp_client_recv_cb);
    espconn_regist_time(pespconn, 300, 1);	// Specific to console only

    ringbuf_reset(console_rx_buffer);
    ringbuf_reset(console_tx_buffer);

    os_sprintf(payload, "CMD>");
    espconn_send(pespconn, payload, os_strlen(payload));
    client_sent_pending = true;
    console_conn = pespconn;
}
#endif				/* REMOTE_CONFIG */

// Timer cb function
void ICACHE_FLASH_ATTR timer_func(void *arg) {
    uint64_t t_new;

    // Do we still have to configure the AP netif? 
    if (do_ip_config) {
	user_set_softap_ip_config();
#ifdef MDNS
	if (config.mdns_mode == 2) {
	    struct mdns_info *info = &mdnsinfo;
	    struct ip_info ipconfig;

	    wifi_get_ip_info(SOFTAP_IF, &ipconfig);

	    info->host_name = "mqtt";
	    info->ipAddr = ipconfig.ip.addr; //ESP8266 SoftAP IP
	    info->server_name = "mqtt";
	    info->server_port = 1883;
	    //info->txt_data[0] = "version = now";

	    espconn_mdns_init(info);
	}
#endif
	do_ip_config = false;
    }

    t_new = get_long_systime();
#ifdef NTP
    if (t_new - t_ntp_resync > config.ntp_interval) {
	ntp_get_time();
	t_ntp_resync = t_new;
    }

    if (ntp_sync_done()) {
	uint8_t *timestr = get_timestr();
	MQTT_local_publish("$SYS/broker/time", timestr, 8, 0, 0);

	// Save system time to RTC memory 
	uint32_t test_magic = MAGIC_NUMBER;
	system_rtc_mem_write (64, &test_magic, 4);
	system_rtc_mem_write (65, (uint32_t *) get_weekday(), 4);
        uint8_t timeval[4];
	timeval[0] = atoi(&timestr[0]);
	timeval[1] = atoi(&timestr[3]);
	timeval[2] = atoi(&timestr[6]);
	system_rtc_mem_write (66, (uint32_t *) timeval, 4);	
#ifdef SCRIPTED
	check_timestamps(timestr);
#endif
    }
#endif
    os_timer_arm(&ptimer, 1000, 0);
}

//Priority 0 Task
static void ICACHE_FLASH_ATTR user_procTask(os_event_t * events) {
    //os_printf("Sig: %d\r\n", events->sig);
    //os_printf("Pub_list: %d\r\n", pub_empty());

    switch (events->sig) {
    case SIG_START_SERVER:
	// Anything else to do here, when the broker has received its IP?
	break;
#ifdef SCRIPTED
    case SIG_TOPIC_RECEIVED:
	{
	    // We check this on any signal
	    // pub_process();
	}
	break;

    case SIG_SCRIPT_LOADED:
	{
	    espconn_disconnect(downloadCon);
	    espconn_delete(downloadCon);
	    os_free(downloadCon->proto.tcp);
	    os_free(downloadCon);
	    // continue to next case and check syntax...
	}
    case SIG_SCRIPT_HTTP_LOADED:
	{
	    if (read_script()) {
		interpreter_syntax_check();
		ringbuf_memcpy_into(console_tx_buffer, tmp_buffer, os_strlen(tmp_buffer));
		ringbuf_memcpy_into(console_tx_buffer, "\r\n", 2);
	    }
	    // continue to next case and print...
	}
#endif
    case SIG_CONSOLE_TX:
	{
	    ringbuf_memcpy_into(console_tx_buffer, "CMD>", 4);
	}

    case SIG_CONSOLE_TX_RAW:
	{
	    struct espconn *pespconn = (struct espconn *)events->par;
	    console_send_response(pespconn, false);

	    if (pespconn != 0 && remote_console_disconnect)
		espconn_disconnect(pespconn);
	    remote_console_disconnect = 0;
	}
	break;

    case SIG_CONSOLE_RX:
	{
	    struct espconn *pespconn = (struct espconn *)events->par;
	    if (pespconn == 0 && system_output == SYSTEM_OUTPUT_NONE) {
		int bytes_count = ringbuf_bytes_used(console_rx_buffer);
		char data[bytes_count];
		ringbuf_memcpy_from(data, console_rx_buffer, bytes_count);
		// overwrite the trailing '\n'
		data[bytes_count-1] = '\0';
#ifdef SCRIPTED
		interpreter_serial_input(data, bytes_count-1);
#endif
	    } else {
		console_handle_command(pespconn);
	    }
	}
	break;

    case SIG_DO_NOTHING:
    default:
	// Intentionally ignoring other signals
	os_printf("Spurious Signal received\r\n");
	break;
    }

    // Check queued messages on any signal
#ifdef SCRIPTED
    pub_process();
#endif
}

/* Callback called when the connection state of the module with an Access Point changes */
void wifi_handle_event_cb(System_Event_t * evt) {
    uint16_t i;
    uint8_t mac_str[20];

    //os_printf("wifi_handle_event_cb: ");
    switch (evt->event) {
    case EVENT_STAMODE_CONNECTED:
	os_printf("connect to ssid %s, channel %d\n",
		  evt->event_info.connected.ssid, evt->event_info.connected.channel);
	my_channel = evt->event_info.connected.channel;
	break;

    case EVENT_STAMODE_DISCONNECTED:
	os_printf("disconnect from ssid %s, reason %d\n",
		  evt->event_info.disconnected.ssid, evt->event_info.disconnected.reason);
	connected = false;

	MQTT_server_cleanupClientCons();

#ifdef SCRIPTED
	interpreter_wifi_disconnect();
#endif
#ifdef MQTT_CLIENT
	if (mqtt_enabled)
// Missing test for local
	    MQTT_Disconnect(&mqttClient);
#endif				/* MQTT_CLIENT */

#ifdef MDNS
	if (config.mdns_mode == 1) {
	    espconn_mdns_close();
	}
#endif
	break;

    case EVENT_STAMODE_AUTHMODE_CHANGE:
	os_printf("mode: %d -> %d\n", evt->event_info.auth_change.old_mode, evt->event_info.auth_change.new_mode);
	break;

    case EVENT_STAMODE_GOT_IP:
	if (config.dns_addr.addr == 0) {
	    dns_ip.addr = dns_getserver(0);
	}

	os_printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR ",dns:" IPSTR "\n",
		  IP2STR(&evt->event_info.got_ip.ip),
		  IP2STR(&evt->event_info.got_ip.mask), IP2STR(&evt->event_info.got_ip.gw), IP2STR(&dns_ip));

	my_ip = evt->event_info.got_ip.ip;
	connected = true;

#ifdef SCRIPTED
	interpreter_wifi_connect();
#endif

#ifdef MQTT_CLIENT
	if (mqtt_enabled)
	    MQTT_Connect(&mqttClient);
#endif

#ifdef NTP
	if (os_strcmp(config.ntp_server, "none") != 0) {
	    ntp_set_server(config.ntp_server);
	    sntp_setservername(1, config.ntp_server);
	    sntp_init();
	}
	set_timezone(config.ntp_timezone);
#endif

#ifdef MDNS
	if (config.mdns_mode == 1) {
	    struct mdns_info *info = &mdnsinfo;

	    info->host_name = "mqtt";
	    info->ipAddr = evt->event_info.got_ip.ip.addr; //ESP8266 station IP
	    info->server_name = "mqtt";
	    info->server_port = 1883;
	    //info->txt_data[0] = "version = now";

	    espconn_mdns_init(info);
	}
#endif

	// Post a Server Start message as the IP has been acquired to Task with priority 0
	system_os_post(user_procTaskPrio, SIG_START_SERVER, 0);
	break;

    case EVENT_SOFTAPMODE_STACONNECTED:
	os_sprintf(mac_str, MACSTR, MAC2STR(evt->event_info.sta_connected.mac));
	os_printf("station: %s join, AID = %d\n", mac_str, evt->event_info.sta_connected.aid);
	break;

    case EVENT_SOFTAPMODE_STADISCONNECTED:
	os_sprintf(mac_str, MACSTR, MAC2STR(evt->event_info.sta_disconnected.mac));
	os_printf("station: %s leave, AID = %d\n", mac_str, evt->event_info.sta_disconnected.aid);
	break;

    default:
	break;
    }
}

void ICACHE_FLASH_ATTR user_set_softap_wifi_config(void) {
    struct softap_config apConfig;

    wifi_softap_get_config(&apConfig);	// Get config first.

    os_memset(apConfig.ssid, 0, 32);
    os_sprintf(apConfig.ssid, "%s", config.ap_ssid);
    os_memset(apConfig.password, 0, 64);
    os_sprintf(apConfig.password, "%s", config.ap_password);
    if (!config.ap_open)
	apConfig.authmode = AUTH_WPA_WPA2_PSK;
    else
	apConfig.authmode = AUTH_OPEN;
    apConfig.ssid_len = 0;	// or its actual length

    apConfig.max_connection = MAX_CLIENTS;	// how many stations can connect to ESP8266 softAP at most.

    // Set ESP8266 softap config
    wifi_softap_set_config(&apConfig);
}

void ICACHE_FLASH_ATTR user_set_softap_ip_config(void) {
    struct ip_info info;
    struct dhcps_lease dhcp_lease;
    struct netif *nif;
    int i;

    // Configure the internal network

    wifi_softap_dhcps_stop();

    info.ip = config.network_addr;
    ip4_addr4(&info.ip) = 1;
    info.gw = info.ip;
    IP4_ADDR(&info.netmask, 255, 255, 255, 0);

    wifi_set_ip_info(1, &info);

    dhcp_lease.start_ip = config.network_addr;
    ip4_addr4(&dhcp_lease.start_ip) = 2;
    dhcp_lease.end_ip = config.network_addr;
    ip4_addr4(&dhcp_lease.end_ip) = 128;
    wifi_softap_set_dhcps_lease(&dhcp_lease);

    wifi_softap_dhcps_start();
}

void ICACHE_FLASH_ATTR user_set_station_config(void) {
    struct station_config stationConf;
    char hostname[40];

    /* Setup AP credentials */
    stationConf.bssid_set = 0;
    os_sprintf(stationConf.ssid, "%s", config.ssid);
    os_sprintf(stationConf.password, "%s", config.password);
    wifi_station_set_config(&stationConf);

    os_sprintf(hostname, "NET_%s", config.ap_ssid);
    hostname[32] = '\0';
    wifi_station_set_hostname(hostname);

    wifi_set_event_handler_cb(wifi_handle_event_cb);

    wifi_station_set_auto_connect(config.auto_connect != 0);
}


bool ICACHE_FLASH_ATTR mqtt_broker_auth(const char* username, const char *password, struct espconn *pesp_conn) {
    //os_printf("connect from " IPSTR "\r\n", IP2STR((ip_addr_t *)&(pesp_conn->proto.tcp->remote_ip)));

    if (os_strcmp(config.mqtt_broker_user, "none") == 0)
	return true;

    if (os_strcmp(username, config.mqtt_broker_user) != 0 ||
	os_strcmp(password, config.mqtt_broker_password) != 0) {
	os_printf("Authentication with %s/%s failed\r\n", username, password);
	return false;
    }
    return true;
}


bool ICACHE_FLASH_ATTR mqtt_broker_connect(struct espconn *pesp_conn, uint16_t client_count) {
    //os_printf("connect from " IPSTR "\r\n", IP2STR((ip_addr_t *)&(pesp_conn->proto.tcp->remote_ip)));

    if (!check_connection_access(pesp_conn, config.mqtt_broker_access)) {
	os_printf("Client disconnected - no mqtt access from the address " IPSTR "\r\n",
		  IP2STR((ip_addr_t *)&(pesp_conn->proto.tcp->remote_ip)));
	return false;
    }

    if (config.max_clients != 0 && client_count > config.max_clients) {
	os_printf("Client disconnected - too many concurrent clients\r\n");
	return false;
    }

    return true;
}


void ICACHE_FLASH_ATTR mqtt_got_retained(retained_entry *topic) {
    if (config.auto_retained)
	save_retainedtopics();
}


#ifdef DNS_RESP
int ICACHE_FLASH_ATTR get_A_Record(uint8_t addr[4], const char domain_name[])
{
  if (strcmp(config.broker_dns_name, domain_name) == 0) {
    *(uint32_t*)addr = config.network_addr.addr;
    return 0;
  } else {
    return -1;
  }
}
#endif


void  user_init() {
    struct ip_info info;

    connected = false;
    do_ip_config = false;
    my_ip.addr = 0;
    t_old = 0;
#ifdef BACKLOG
    backlog_buffer = NULL;
#endif

    console_rx_buffer = ringbuf_new(MAX_CON_CMD_SIZE);
    console_tx_buffer = ringbuf_new(MAX_CON_SEND_SIZE);
#ifdef GPIO
    gpio_init();
#endif
    init_long_systime();

    // Temporarily initialize the UART with 115200
    UART_init_console(BIT_RATE_115200, 0, console_rx_buffer, console_tx_buffer);

    os_printf("\r\n\r\nuMQTT Broker %s starting\r\n", ESP_UBROKER_VERSION);

    // Load config
    int config_res = config_load(&config);

    if (config_res != 0) {
	// Clear retained topics slot
	blob_zero(RETAINED_SLOT, MAX_RETAINED_LEN);
    }

#ifdef NTP
    // Restore system time from RTC memory (if found)
    uint32_t test_magic;
    system_rtc_mem_read (64, &test_magic, 4);
    if (test_magic == MAGIC_NUMBER) {
	char weekday[4];
	system_rtc_mem_read (65, (int *)weekday, 4);
	set_weekday_local(weekday);
	uint8_t time[4];
	system_rtc_mem_read (66, (int *)time, 4);
	set_time_local(time[0], time[1], time[2]);
    }
#endif

#ifdef SCRIPTED
    loop_count = loop_time = 0;
    script_enabled = false;
    if ((config_res == 0) && read_script()) {
	if (interpreter_syntax_check() != -1) {
	    bool lockstat = config.locked;
	    config.locked = false;

	    script_enabled = true;
	    interpreter_config();

	    config.locked = lockstat;
	} else {
	    os_printf("ERROR in script: %s\r\nScript disabled\r\n", tmp_buffer);
	}
    } else {
	// Clear script and vars
	blob_zero(SCRIPT_SLOT, MAX_SCRIPT_SIZE);
	blob_zero(VARS_SLOT, MAX_FLASH_SLOTS * FLASH_SLOT_LEN);
    }
#endif

    // Set bit rate to config value
    uart_div_modify(0, UART_CLK_FREQ / config.bit_rate);

    system_output = config.system_output;
    if (system_output < SYSTEM_OUTPUT_INFO) {
	// all system output to /dev/null
	system_set_os_print(0);
	os_install_putc1(void_write_char);
    }
    if (system_output < SYSTEM_OUTPUT_CMD) {
	// disable UART echo
	UART_Echo(0);
    }

    // Configure the AP and start it, if required

    if (config.dns_addr.addr != 0)
	// We have a static DNS server
	dns_ip.addr = config.dns_addr.addr;

    if (config.ap_on) {
	wifi_set_opmode(STATIONAP_MODE);
	user_set_softap_wifi_config();
	do_ip_config = true;
#ifdef DNS_RESP
        if (strcmp(config.broker_dns_name, "none")!=0) {
	    dns_resp_init(DNS_MODE_AP);
	}
#endif
    } else {
	wifi_set_opmode(STATION_MODE);
    }

    if (config.my_addr.addr != 0) {
	wifi_station_dhcpc_stop();
	info.ip.addr = config.my_addr.addr;
	info.gw.addr = config.my_gw.addr;
	info.netmask.addr = config.my_netmask.addr;
	wifi_set_ip_info(STATION_IF, &info);
	espconn_dns_setserver(0, &dns_ip);
    }

#ifdef MDNS
    wifi_set_broadcast_if(STATIONAP_MODE);
#endif

#ifdef REMOTE_CONFIG
    if (config.config_port != 0) {
	os_printf("Starting Console TCP Server on port %d\r\n", config.config_port);
	struct espconn *pCon = (struct espconn *)os_zalloc(sizeof(struct espconn));

	/* Equivalent to bind */
	pCon->type = ESPCONN_TCP;
	pCon->state = ESPCONN_NONE;
	pCon->proto.tcp = (esp_tcp *) os_zalloc(sizeof(esp_tcp));
	pCon->proto.tcp->local_port = config.config_port;

	/* Register callback when clients connect to the server */
	espconn_regist_connectcb(pCon, tcp_client_connected_cb);

	/* Put the connection in accept mode */
	espconn_accept(pCon);
    }
#endif

#ifdef MQTT_CLIENT
    mqtt_connected = false;
    mqtt_enabled = (os_strcmp(config.mqtt_host, "none") != 0);
    if (mqtt_enabled) {
	MQTT_InitConnection(&mqttClient, config.mqtt_host, config.mqtt_port, config.mqtt_ssl);

	if (os_strcmp(config.mqtt_user, "none") == 0) {
	    MQTT_InitClient(&mqttClient, config.mqtt_id, 0, 0, 120, 1);
	} else {
	    MQTT_InitClient(&mqttClient, config.mqtt_id, config.mqtt_user, config.mqtt_password, 120, 1);
	}
//      MQTT_InitLWT(&mqttClient, "/lwt", "offline", 0, 0);
	MQTT_OnConnected(&mqttClient, mqttConnectedCb);
	MQTT_OnDisconnected(&mqttClient, mqttDisconnectedCb);
	MQTT_OnPublished(&mqttClient, mqttPublishedCb);
	MQTT_OnData(&mqttClient, mqttDataCb);
    }
#endif				/* MQTT_CLIENT */

    remote_console_disconnect = 0;
    console_conn = NULL;

    // Now start the STA-Mode
    user_set_station_config();

    system_update_cpu_freq(config.clock_speed);

    // Start the broker only if it accessible
    if (config.mqtt_broker_access != 0) {
	espconn_tcp_set_max_con(15);
	os_printf("Max number of TCP clients: %d\r\n", espconn_tcp_get_max_con());

	MQTT_server_onData(MQTT_local_DataCallback);
	MQTT_server_onConnect(mqtt_broker_connect);
	MQTT_server_onAuth(mqtt_broker_auth);

	MQTT_server_start(config.mqtt_broker_port , config.max_subscriptions,
			  config.max_retained_messages);
	load_retainedtopics();
	set_on_retainedtopic_cb(mqtt_got_retained);
    }

    //Start task
    system_os_task(user_procTask, user_procTaskPrio, user_procTaskQueue, user_procTaskQueueLen);

#ifdef SCRIPTED
    interpreter_init();
#endif

    // Start the timer
    os_timer_setfn(&ptimer, timer_func, 0);
    os_timer_arm(&ptimer, 500, 0);
}
