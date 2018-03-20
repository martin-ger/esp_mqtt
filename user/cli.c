#include "c_types.h"
#include "mem.h"
#include "ets_sys.h"
#include "osapi.h"
#include "os_type.h"

#include "global.h"
#include "sys_time.h"

#define os_sprintf_flash(str, fmt, ...) do {	\
	static const char flash_str[] ICACHE_RODATA_ATTR STORE_ATTR = fmt;	\
	int flen = (sizeof(flash_str) + 4) & ~3;	\
	char *f = (char *)os_malloc(flen);	\
	os_memcpy(f, flash_str, flen);	\
	ets_vsprintf(str, f,  ##__VA_ARGS__);	\
	os_free(f);	\
	} while(0)

static char INVALID_LOCKED[] = "Invalid command. Config locked\r\n";
static char INVALID_NUMARGS[] = "Invalid number of arguments\r\n";
static char INVALID_ARG[] = "Invalid argument\r\n";

bool ICACHE_FLASH_ATTR printf_topic(topic_entry * topic, void *user_data) {
    uint8_t *response = (uint8_t *) user_data;

    os_sprintf(response, "%s: \"%s\" (QoS %d)\r\n",
	       topic->clientcon !=
	       LOCAL_MQTT_CLIENT ? topic->clientcon->connect_info.client_id : "local", topic->topic, topic->qos);
    to_console(response);
    return false;
}

bool ICACHE_FLASH_ATTR printf_retainedtopic(retained_entry * entry, void *user_data) {
    uint8_t *response = (uint8_t *) user_data;

    os_sprintf(response, "\"%s\" len: %d (QoS %d)\r\n", entry->topic, entry->data_len, entry->qos);
    to_console(response);
    return false;
}

#ifdef ALLOW_SCANNING
void ICACHE_FLASH_ATTR scan_done(void *arg, STATUS status) {
    char response[128];

    if (status == OK) {
	struct bss_info *bss_link = (struct bss_info *)arg;

	ringbuf_memcpy_into(console_tx_buffer, "\r", 1);
	while (bss_link != NULL) {
	    os_sprintf(response, "%d,\"%s\",%d,\"" MACSTR "\",%d\r\n",
		       bss_link->authmode, bss_link->ssid, bss_link->rssi, MAC2STR(bss_link->bssid), bss_link->channel);
	    to_console(response);
	    bss_link = bss_link->next.stqe_next;
	}
    } else {
	os_sprintf(response, "scan fail !!!\r\n");
	to_console(response);
    }
    system_os_post(user_procTaskPrio, SIG_CONSOLE_TX, (ETSParam) console_conn);
}
#endif

int ICACHE_FLASH_ATTR parse_str_into_tokens(char *str, char **tokens, int max_tokens)
{
char    *p, *q, *end;
int     token_count = 0;
bool    in_token = false;

   // preprocessing
   for (p = q = str; *p != 0; p++) {
	if (*(p) == '%' && *(p+1) != 0 && *(p+2) != 0) {
	   // quoted hex
		uint8_t a;
		p++;
		if (*p <= '9')
		    a = *p - '0';
		else
		    a = toupper(*p) - 'A' + 10;
		a <<= 4;
		p++;
		if (*p <= '9')
		    a += *p - '0';
		else
		    a += toupper(*p) - 'A' + 10;
		*q++ = a;
	} else if (*p == '\\' && *(p+1) != 0) {
	   // next char is quoted - just copy it, skip this one
	   *q++ = *++p;
	} else if (*p == 8) {
	   // backspace - delete previous char
	   if (q != str) q--;
	} else if (*p <= ' ') {
	   // mark this as whitespace
	   *q++ = 0;
	} else {
	   *q++ = *p;
	}
   }

   end = q;
   *q = 0;

   // cut into tokens
   for (p = str; p != end; p++) {
	if (*p == 0) {
	   if (in_token) {
		in_token = false;
	   }
	} else {
	   if (!in_token) {
		tokens[token_count++] = p;
		if (token_count == max_tokens)
		   return token_count;
		in_token = true;
	   }  
	}
   }
   return token_count;
}

void ICACHE_FLASH_ATTR console_handle_command(struct espconn *pespconn) {
#define MAX_CMD_TOKENS 6

    char cmd_line[MAX_CON_CMD_SIZE + 1];
    char response[256];
    char *tokens[MAX_CMD_TOKENS];

    int bytes_count, nTokens;

    bytes_count = ringbuf_bytes_used(console_rx_buffer);
    ringbuf_memcpy_from(cmd_line, console_rx_buffer, bytes_count);

    cmd_line[bytes_count] = 0;
    response[0] = 0;

    nTokens = parse_str_into_tokens(cmd_line, tokens, MAX_CMD_TOKENS);

    if (nTokens == 0) {
	char c = '\n';
	ringbuf_memcpy_into(console_tx_buffer, &c, 1);
	goto command_handled_2;
    }

    if (strcmp(tokens[0], "help") == 0) {
	os_sprintf_flash(response, "show [config|stats|mqtt]\r\nsave\r\nreset [factory]\r\nlock [<password>]\r\nunlock <password>\r\nquit\r\n");
	to_console(response);
#ifdef ALLOW_SCANNING
	os_sprintf_flash(response, "scan\r\n");
	to_console(response);
#endif
	os_sprintf_flash(response, "set [ssid|password|auto_connect|ap_ssid|ap_password|ap_on|ap_open] <val>\r\n");
	to_console(response);
	os_sprintf_flash(response, "set [network|dns|ip|netmask|gw] <val>\r\n");
	to_console(response);
	os_sprintf_flash(response, "set [config_port|config_access|bitrate|system_output] <val>\r\n");
	to_console(response);
	os_sprintf_flash(response, "set [broker_port|broker_user|broker_password|broker_access|broker_clients] <val>\r\n");
	to_console(response);
	os_sprintf_flash(response, "set [broker_subscriptions|broker_retained_messages|broker_autoretain] <val>\r\n");
	to_console(response);
	os_sprintf_flash(response, "delete_retained|save_retained\r\n");
	to_console(response);
	os_sprintf_flash(response, "publish [local|remote] <topic> <data> [retained]\r\n");
	to_console(response);
#ifdef SCRIPTED
	os_sprintf_flash(response, "script <port>|<url>|delete\r\nshow [script|vars]\r\n");
	to_console(response);
#ifdef GPIO
#ifdef GPIO_PWM
	os_sprintf_flash(response, "set pwm_period <val>\r\n");
	to_console(response);
#endif
#endif
#endif
#ifdef NTP
	os_sprintf_flash(response, "time\r\nset [ntp_server|ntp_interval|ntp_timezone|ntp_time|ntp_weekday] <val>\r\n");
	to_console(response);
#endif
#ifdef MQTT_CLIENT
	os_sprintf_flash(response, "set [mqtt_host|mqtt_port|mqtt_ssl|mqtt_user|mqtt_password|mqtt_id] <val>\r\n");
	to_console(response);
#endif

	goto command_handled_2;
    }

    if (strcmp(tokens[0], "show") == 0) {
	int16_t i;
	ip_addr_t i_ip;

	if (nTokens == 1 || (nTokens == 2 && strcmp(tokens[1], "config") == 0)) {
	    os_sprintf(response, "Version %s (build: %s)\r\n", ESP_UBROKER_VERSION, __TIMESTAMP__);
	    to_console(response);

	    os_sprintf(response, "STA: SSID:%s PW:%s%s\r\n",
		       config.ssid,
		       config.locked ? "***" : (char *)config.password, config.auto_connect ? "" : " [AutoConnect:0]");
	    to_console(response);

	    os_sprintf(response, "AP:  SSID:%s PW:%s%s%s IP:%d.%d.%d.%d/24\r\n",
		       config.ap_ssid,
		       config.locked ? "***" : (char *)config.ap_password,
		       config.ap_open ? " [open]" : "",
		       config.ap_on ? "" : " [disabled]", IP2STR(&config.network_addr));
	    to_console(response);

	    // if static IP, add it
	    os_sprintf(response,
		       config.my_addr.addr ?
		       "Static IP: %d.%d.%d.%d Netmask: %d.%d.%d.%d Gateway: %d.%d.%d.%d\r\n"
		       : "", IP2STR(&config.my_addr), IP2STR(&config.my_netmask), IP2STR(&config.my_gw));
	    to_console(response);
	    // if static DNS, add it
	    os_sprintf(response, config.dns_addr.addr ? "DNS: %d.%d.%d.%d\r\n" : "", IP2STR(&config.dns_addr));
	    to_console(response);
#ifdef MDNS
	    if (config.mdns_mode) {
		os_sprintf(response, "mDNS: %s interface\r\n", config.mdns_mode==1 ? "STA": "SoftAP");
		to_console(response);
	    }
#endif
#ifdef REMOTE_CONFIG
	    if (config.config_port == 0 || config.config_access == 0) {
		os_sprintf(response, "No network console access\r\n");
	    } else {
		os_sprintf(response, "Network console access on port %d (mode %d)\r\n", config.config_port, config.config_access);
	    }
	    to_console(response);
#endif

	    os_sprintf(response, "MQTT broker max. subscription: %d\r\nMQTT broker max. retained messages: %d%s\r\n",
		       config.max_subscriptions, config.max_retained_messages, config.auto_retained?" (auto saved)":"");
	    to_console(response);

	    if (config.mqtt_broker_port != MQTT_PORT) {
		os_sprintf(response, "MQTT broker port: %d\r\n", config.mqtt_broker_port);
		to_console(response);
	    }
	    if (config.max_clients != 0) {
		os_sprintf(response, "MQTT broker max. clients: %d\r\n", config.max_clients);
		to_console(response);
	    }

	    if (os_strcmp(config.mqtt_broker_user, "none") != 0) {
		os_sprintf(response,
			   "MQTT broker username: %s\r\nMQTT broker password: %s\r\n",
			   config.mqtt_broker_user,
			   config.locked ? "***" : (char *)config.mqtt_broker_password);
		to_console(response);
	    }
	    response[0] = '\0';
	    if (config.mqtt_broker_access == LOCAL_ACCESS)
		os_sprintf(response, "MQTT broker: local access only\r\n");
	    if (config.mqtt_broker_access == REMOTE_ACCESS)
		os_sprintf(response, "MQTT broker: remote access only\r\n");
	    if (config.mqtt_broker_access == 0)
		os_sprintf(response, "MQTT broker: disabled\r\n");
	    to_console(response);
#ifdef MQTT_CLIENT
	    os_sprintf(response, "MQTT client %s\r\n", mqtt_enabled ? "enabled" : "disabled");
	    to_console(response);

	    if (os_strcmp(config.mqtt_host, "none") != 0) {
		os_sprintf(response,
			   "MQTT client host: %s\r\nMQTT client port: %d\r\nMQTT client user: %s\r\nMQTT client password: %s\r\nMQTT client id: %s\r\nMQTT SSL: %s\r\n",
			   config.mqtt_host, config.mqtt_port, config.mqtt_user,
			   config.locked ? "***" : (char *)config.mqtt_password, config.mqtt_id,
			   config.mqtt_ssl ? "on" : "off");
		to_console(response);
	    }
#endif
#ifdef NTP
	    if (os_strcmp(config.ntp_server, "none") != 0) {
		os_sprintf(response,
			   "NTP server: %s (interval: %d s, tz: %d)\r\n",
			   config.ntp_server, config.ntp_interval / 1000000, config.ntp_timezone);
		to_console(response);
	    }
#endif
	    os_sprintf(response, "Clock speed: %d\r\n", config.clock_speed);
	    to_console(response);

	    os_sprintf(response, "Serial bitrate: %d\r\n", config.bit_rate);
	    to_console(response);
	    if (config.system_output < SYSTEM_OUTPUT_INFO) {
                os_sprintf(response, "System output: %s\r\n", config.system_output==SYSTEM_OUTPUT_NONE?"none":"command reply");
		to_console(response);
	    }
	    goto command_handled_2;
	}

	if (nTokens == 2 && strcmp(tokens[1], "stats") == 0) {
	    uint32_t time = (uint32_t) (get_long_systime() / 1000000);
	    int16_t i;

	    os_sprintf(response, "System uptime: %d:%02d:%02d\r\n", time / 3600, (time % 3600) / 60, time % 60);
	    to_console(response);

	    os_sprintf(response, "Free mem: %d\r\n", system_get_free_heap_size());
	    to_console(response);
#ifdef SCRIPTED
	    os_sprintf(response, "Interpreter loop: %d (%d us)\r\n", loop_count, loop_time);
	    to_console(response);
#endif
	    if (connected) {
		os_sprintf(response, "External IP-address: " IPSTR "\r\n", IP2STR(&my_ip));
	    } else {
		os_sprintf_flash(response, "Not connected to AP\r\n");
	    }
	    to_console(response);
	    if (config.ap_on)
		os_sprintf(response, "%d Station%s connected to AP\r\n",
			   wifi_softap_get_station_num(), wifi_softap_get_station_num() == 1 ? "" : "s");
	    else
		os_sprintf_flash(response, "AP disabled\r\n");
	    to_console(response);
#ifdef NTP
	    if (ntp_sync_done()) {
		os_sprintf(response, "NTP synced: %s \r\n", get_timestr());
	    } else {
		os_sprintf_flash(response, "NTP no sync\r\n");
	    }
	    to_console(response);
#endif
	    goto command_handled_2;
	}

	if (nTokens == 2 && strcmp(tokens[1], "mqtt") == 0) {
	    if (config.locked) {
		os_sprintf(response, INVALID_LOCKED);
		goto command_handled;
	    }

	    MQTT_ClientCon *clientcon;
	    int ccnt = 0;

	    os_sprintf(response, "Current clients: %d\r\n", MQTT_server_countClientCon());
	    to_console(response);
	    for (clientcon = clientcon_list; clientcon != NULL; clientcon = clientcon->next, ccnt++) {
		os_sprintf(response, "%s%s", clientcon->connect_info.client_id, clientcon->next != NULL ? ", " : "");
		to_console(response);
	    }
	    os_sprintf(response, "%sCurrent subsriptions:\r\n", ccnt ? "\r\n" : "");
	    to_console(response);
	    iterate_topics(printf_topic, response);
	    os_sprintf_flash(response, "Retained topics:\r\n");
	    to_console(response);
	    iterate_retainedtopics(printf_retainedtopic, response);
#ifdef MQTT_CLIENT
	    os_sprintf(response, "MQTT client %s\r\n", mqtt_connected ? "connected" : "disconnected");
	    to_console(response);
#endif
#ifdef SCRIPTED
	    os_sprintf(response, "Script %s\r\n", script_enabled ? "enabled" : "disabled");
	    to_console(response);
#endif
	    goto command_handled_2;
	}
#ifdef BACKLOG
	if (nTokens >= 2 && strcmp(tokens[1], "backlog") == 0) {
	    uint16_t len;
	    if (backlog_buffer == NULL)
		goto command_handled_2;
	    while (ringbuf_bytes_free(console_tx_buffer) && (len=ringbuf_bytes_used(backlog_buffer))) {
		if (len > sizeof(response)-1)
		    len = sizeof(response)-1;
		ringbuf_memcpy_from(response, backlog_buffer, len);
		to_console(response);
	    }

	    goto command_handled_2;
	}
#endif
#ifdef SCRIPTED
	if (nTokens >= 2 && strcmp(tokens[1], "script") == 0) {
	    if (config.locked) {
		os_sprintf(response, INVALID_LOCKED);
		goto command_handled;
	    }

	    uint32_t line_count, char_count, start_line = 1;
	    if (nTokens == 3)
		start_line = atoi(tokens[2]);

	    uint32_t size = get_script_size();
	    if (size == 0)
		goto command_handled;

	    uint8_t *script = (uint8_t *) os_malloc(size);
	    uint8_t *p;
	    bool nl;

	    if (script == 0) {
		os_sprintf_flash(response, "Out of memory");
		goto command_handled;
	    }

	    blob_load(SCRIPT_SLOT, (uint32_t *) script, size);

	    p = script + 4;
	    for (line_count = 1; line_count < start_line && *p != 0; p++) {
		if (*p == '\n')
		    line_count++;
	    }
	    nl = true;
	    for (char_count = 0; *p != 0 && char_count < MAX_CON_SEND_SIZE - 20; p++, char_count++) {
		if (nl) {
		    os_sprintf(response, "\r%4d: ", line_count);
		    char_count += 7;
		    to_console(response);
		    line_count++;
		    nl = false;
		}
		ringbuf_memcpy_into(console_tx_buffer, p, 1);
		if (*p == '\n')
		    nl = true;
	    }
	    if (*p == 0) {
		ringbuf_memcpy_into(console_tx_buffer, "\r\n--end--", 9);
	    } else {
		ringbuf_memcpy_into(console_tx_buffer, "...", 3);
	    }
	    ringbuf_memcpy_into(console_tx_buffer, "\r\n", 2);

	    os_free(script);
	    goto command_handled_2;
	}

	if (nTokens >= 2 && strcmp(tokens[1], "vars") == 0) {
	    if (config.locked) {
		os_sprintf(response, INVALID_LOCKED);
		goto command_handled;
	    }
	    int i;

	    if (script_enabled) {
		for (i = 0; i < MAX_VARS; i++) {
		    if (!vars[i].free) {
			os_sprintf(response, "%s: %s\r\n", vars[i].name, vars[i].data);
			to_console(response);
		    }
		}
	    }

	    uint8_t slots[MAX_FLASH_SLOTS*FLASH_SLOT_LEN];
	    blob_load(VARS_SLOT, (uint32_t *)slots, sizeof(slots));

	    for (i = 0; i < MAX_FLASH_SLOTS; i++) {
		os_sprintf(response, "@%d: %s\r\n", i+1, &slots[i*FLASH_SLOT_LEN]);
		to_console(response);
	    }
	    goto command_handled_2;
	}
#endif
    }

    if (strcmp(tokens[0], "save") == 0) {
	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	if (nTokens == 1 || (nTokens == 2 && strcmp(tokens[1], "config") == 0)) {
	    config_save(&config);
	    os_sprintf_flash(response, "Config saved\r\n");
	    goto command_handled;
	}
    }
#ifdef ALLOW_SCANNING
    if (strcmp(tokens[0], "scan") == 0) {
	wifi_station_scan(NULL, scan_done);
	os_sprintf_flash(response, "Scanning...\r\n");
	goto command_handled;
    }
#endif
#ifdef NTP
    if (strcmp(tokens[0], "time") == 0) {
	os_sprintf(response, "%s %s\r\n", get_weekday(), get_timestr());
	goto command_handled;
    }
#endif
    if (strcmp(tokens[0], "reset") == 0) {
	if (config.locked && pespconn != NULL) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}
	if (nTokens == 2 && strcmp(tokens[1], "factory") == 0) {
	    config_load_default(&config);
	    config_save(&config);
#ifdef SCRIPTED
	    // Clear script, vars, and retained topics
	    blob_zero(SCRIPT_SLOT, MAX_SCRIPT_SIZE);
	    blob_zero(VARS_SLOT, MAX_FLASH_SLOTS * FLASH_SLOT_LEN);
	    blob_zero(RETAINED_SLOT, MAX_RETAINED_LEN);
#endif
	}

	save_retainedtopics();

	os_printf("Restarting ... \r\n");
	system_restart();	// if it works this will not return

	os_sprintf(response, "Reset failed\r\n");
	goto command_handled;
    }

    if (strcmp(tokens[0], "quit") == 0) {
	remote_console_disconnect = 1;
	os_sprintf_flash(response, "Quitting console\r\n");
	goto command_handled;
    }
#ifdef SCRIPTED
    if (strcmp(tokens[0], "script") == 0) {
	uint16_t port;

	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	if (nTokens != 2) {
	    os_sprintf(response, INVALID_NUMARGS);
	    goto command_handled;
	}

	if (strcmp(tokens[1], "delete") == 0) {
#ifdef GPIO
	    stop_gpios();
#endif
	    script_enabled = false;
	    if (my_script != NULL)
		free_script();
	    blob_zero(0, MAX_SCRIPT_SIZE);
	    blob_zero(1, MAX_FLASH_SLOTS * FLASH_SLOT_LEN);
	    os_sprintf_flash(response, "Script deleted\r\n");
	    goto command_handled;
	}

	if (!isdigit(tokens[1][0])) {
	    scriptcon = pespconn;
	    http_get(tokens[1], "", http_script_cb);
	    os_sprintf(response, "HTTP request to %s started\r\n", tokens[1]);
	    goto command_handled;  
	}

	port = atoi(tokens[1]);
	if (port == 0) {
	    os_sprintf_flash(response, "Invalid port\r\n");
	    goto command_handled;
	}
	// delete and disable existing script
#ifdef GPIO
	stop_gpios();
#endif
	script_enabled = false;
	if (my_script != NULL)
	    free_script();

	scriptcon = pespconn;
	downloadCon = (struct espconn *)os_zalloc(sizeof(struct espconn));

	/* Equivalent to bind */
	downloadCon->type = ESPCONN_TCP;
	downloadCon->state = ESPCONN_NONE;
	downloadCon->proto.tcp = (esp_tcp *) os_zalloc(sizeof(esp_tcp));
	downloadCon->proto.tcp->local_port = port;

	/* Register callback when clients connect to the server */
	espconn_regist_connectcb(downloadCon, script_connected_cb);

	/* Put the connection in accept mode */
	espconn_accept(downloadCon);

	os_sprintf(response, "Waiting for script upload on port %d\r\n", port);
	goto command_handled;
    }
#endif
    if (strcmp(tokens[0], "lock") == 0) {
	if (config.locked) {
	    os_sprintf_flash(response, "Config already locked\r\n");
	    goto command_handled;
	}
	if (nTokens == 1) {
	    if (os_strlen(config.lock_password) == 0) {
		os_sprintf_flash(response, "No password defined\r\n");
		goto command_handled;
	    }
	}
	else if (nTokens == 2) {
	    os_sprintf(config.lock_password, "%s", tokens[1]);
	}
	else {
	    os_sprintf(response, INVALID_NUMARGS);
	    goto command_handled;
	}
	config.locked = 1;
	config_save(&config);
	os_sprintf(response, "Config locked (pw: %s)\r\n", config.lock_password);
	goto command_handled;
    }

    if (strcmp(tokens[0], "unlock") == 0) {
	if (nTokens != 2) {
	    os_sprintf(response, INVALID_NUMARGS);
	} else if (os_strcmp(tokens[1], config.lock_password) == 0) {
	    config.locked = 0;
	    config_save(&config);
	    os_sprintf_flash(response, "Config unlocked\r\n");
	} else {
	    os_sprintf_flash(response, "Unlock failed. Invalid password\r\n");
	}
	goto command_handled;
    }

    if (strcmp(tokens[0], "publish") == 0)
    {
	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	uint8_t retained = 0;

	if (nTokens < 4 || nTokens > 5) {
            os_sprintf(response, INVALID_NUMARGS);
            goto command_handled;
	}
	if (nTokens == 5) {
	    if (strcmp(tokens[4], "retained")==0) {
		retained = 1;
	    } else {
        	os_sprintf(response, "Invalid arg %s\r\n", tokens[4]);
        	goto command_handled;
	    }
	}
	if (strcmp(tokens[1], "local") == 0) {
	    MQTT_local_publish(tokens[2], tokens[3], os_strlen(tokens[3]), 0, retained);
	}
#ifdef MQTT_CLIENT
	else if (strcmp(tokens[1], "remote") == 0 && mqtt_connected) {
	    MQTT_Publish(&mqttClient, tokens[2], tokens[3], os_strlen(tokens[3]), 0, retained);
	}
#endif
	else {
            os_sprintf(response, "Invalid arg %s\r\n", tokens[1]);
            goto command_handled;
	}
	os_sprintf_flash(response, "Published topic\r\n");
	goto command_handled;
    }

    if (strcmp(tokens[0], "delete_retained") == 0)
    {
	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	if (nTokens != 1) {
            os_sprintf(response, INVALID_NUMARGS);
            goto command_handled;
	}

	delete_retainedtopics();

	os_sprintf_flash(response, "Deleted retained topics\r\n");
	goto command_handled;
    }

    if (strcmp(tokens[0], "save_retained") == 0)
    {
	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	if (nTokens != 1) {
            os_sprintf(response, INVALID_NUMARGS);
            goto command_handled;
	}

	bool success = save_retainedtopics();

	os_sprintf(response, "Saved retained topics %ssuccessfully\r\n", success?"":"un");
	goto command_handled;
    }
/*
    if (strcmp(tokens[0], "load_retained") == 0)
    {
	if (nTokens != 1) {
            os_sprintf(response, INVALID_NUMARGS);
            goto command_handled;
	}

	bool success = load_retainedtopics();

	os_sprintf(response, "Loaded retained topics %ssuccessfully\r\n", success?"":"un");
	goto command_handled;
    }
*/
    if (strcmp(tokens[0], "set") == 0) {
	if (config.locked) {
	    os_sprintf(response, INVALID_LOCKED);
	    goto command_handled;
	}

	/*
	 * For set commands atleast 2 tokens "set" "parameter" "value" is needed
	 * hence the check
	 */
	if (nTokens < 3) {
	    os_sprintf(response, INVALID_NUMARGS);
	    goto command_handled;
	} else {
	    // atleast 3 tokens, proceed
	    if (strcmp(tokens[1], "ssid") == 0) {
		os_sprintf(config.ssid, "%s", tokens[2]);
		config.auto_connect = 1;
		os_sprintf_flash(response, "SSID set (auto_connect = 1)\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "password") == 0) {
		os_sprintf(config.password, "%s", tokens[2]);
		os_sprintf_flash(response, "Password set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "auto_connect") == 0) {
		config.auto_connect = atoi(tokens[2]);
		os_sprintf_flash(response, "Auto Connect set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ap_ssid") == 0) {
		os_sprintf(config.ap_ssid, "%s", tokens[2]);
		os_sprintf_flash(response, "AP SSID set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ap_password") == 0) {
		if (os_strlen(tokens[2]) < 8) {
		    os_sprintf_flash(response, "Password to short (min. 8)\r\n");
		} else {
		    os_sprintf(config.ap_password, "%s", tokens[2]);
		    config.ap_open = 0;
		    os_sprintf_flash(response, "AP Password set\r\n");
		}
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ap_open") == 0) {
		config.ap_open = atoi(tokens[2]);
		os_sprintf_flash(response, "Open Auth set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ap_on") == 0) {
		if (atoi(tokens[2])) {
		    if (!config.ap_on) {
			wifi_set_opmode(STATIONAP_MODE);
			user_set_softap_wifi_config();
			do_ip_config = true;
			config.ap_on = true;
			os_sprintf_flash(response, "AP on\r\n");
		    } else {
			os_sprintf_flash(response, "AP already on\r\n");
		    }

		} else {
		    if (config.ap_on) {
			wifi_set_opmode(STATION_MODE);
#ifdef MDNS
			if (config.mdns_mode == 2) {
			    espconn_mdns_close();
			}
#endif
			config.ap_on = false;
			os_sprintf_flash(response, "AP off\r\n");
		    } else {
			os_sprintf_flash(response, "AP already off\r\n");
		    }
		}
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "speed") == 0) {
		uint16_t speed = atoi(tokens[2]);
		bool succ = system_update_cpu_freq(speed);
		if (succ)
		    config.clock_speed = speed;
		os_sprintf(response, "Clock speed update %s\r\n", succ ? "successful" : "failed");
		goto command_handled;
	    }

            if (strcmp(tokens[1],"bitrate") == 0)
            {
                config.bit_rate = atoi(tokens[2]);
                os_sprintf(response, "Bitrate set to %d\r\n", config.bit_rate);
                goto command_handled;
            }

            if (strcmp(tokens[1],"system_output") == 0)
            {
                config.system_output = atoi(tokens[2]);
                os_sprintf(response, "System output set to %d\r\n", config.system_output);
                goto command_handled;
            }

	    if (strcmp(tokens[1], "network") == 0) {
		config.network_addr.addr = ipaddr_addr(tokens[2]);
		ip4_addr4(&config.network_addr) = 0;
		os_sprintf(response, "Network set to %d.%d.%d.%d\r\n", IP2STR(&config.network_addr));
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "dns") == 0) {
		if (os_strcmp(tokens[2], "dhcp") == 0) {
		    config.dns_addr.addr = 0;
		    os_sprintf_flash(response, "DNS from DHCP\r\n");
		} else {
		    config.dns_addr.addr = ipaddr_addr(tokens[2]);
		    os_sprintf(response, "DNS set to %d.%d.%d.%d\r\n", IP2STR(&config.dns_addr));
		    if (config.dns_addr.addr) {
			dns_ip.addr = config.dns_addr.addr;
		    }
		}
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ip") == 0) {
		if (os_strcmp(tokens[2], "dhcp") == 0) {
		    config.my_addr.addr = 0;
		    os_sprintf_flash(response, "IP from DHCP\r\n");
		} else {
		    config.my_addr.addr = ipaddr_addr(tokens[2]);
		    os_sprintf(response, "IP address set to %d.%d.%d.%d\r\n", IP2STR(&config.my_addr));
		}
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "netmask") == 0) {
		config.my_netmask.addr = ipaddr_addr(tokens[2]);
		os_sprintf(response, "IP netmask set to %d.%d.%d.%d\r\n", IP2STR(&config.my_netmask));
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "gw") == 0) {
		config.my_gw.addr = ipaddr_addr(tokens[2]);
		os_sprintf(response, "Gateway set to %d.%d.%d.%d\r\n", IP2STR(&config.my_gw));
		goto command_handled;
	    }
#ifdef MDNS
	    if (strcmp(tokens[1], "mdns_mode") == 0) {
		config.mdns_mode = atoi(tokens[2]);
		os_sprintf(response, "mDNS mode set to %d\r\n", config.mdns_mode);
		goto command_handled;
	    }
#endif
#ifdef REMOTE_CONFIG
	    if (strcmp(tokens[1], "config_port") == 0) {
		config.config_port = atoi(tokens[2]);
		if (config.config_port == 0)
		    os_sprintf_flash(response, "WARNING: if you save this, remote console access will be disabled!\r\n");
		else
		    os_sprintf(response, "Config port set to %d\r\n", config.config_port);
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "config_access") == 0) {
		config.config_access = atoi(tokens[2]) & (LOCAL_ACCESS | REMOTE_ACCESS);
		if (config.config_access == 0)
		    os_sprintf_flash(response, "WARNING: if you save this, remote console access will be disabled!\r\n");
		else
		    os_sprintf(response, "Config access set\r\n");
		goto command_handled;
	    }
#endif
	    if (strcmp(tokens[1], "broker_subscriptions") == 0) {
		config.max_subscriptions = atoi(tokens[2]);
		os_sprintf_flash(response, "Broker subscriptions set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_retained_messages") == 0) {
		config.max_retained_messages = atoi(tokens[2]);
		os_sprintf_flash(response, "Broker retained messages set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_clients") == 0) {
		config.max_clients = atoi(tokens[2]);
		os_sprintf_flash(response, "Broker max clients set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_port") == 0) {
		config.mqtt_broker_port = atoi(tokens[2]);
		os_sprintf_flash(response, "Broker port set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_user") == 0) {
		os_strncpy(config.mqtt_broker_user, tokens[2], 32);
		config.mqtt_broker_user[31] = '\0';
		os_sprintf_flash(response, "Broker username set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_password") == 0) {
		if (os_strcmp(tokens[2], "none") == 0) {
		    config.mqtt_broker_password[0] = '\0';
		} else {
		    os_strncpy(config.mqtt_broker_password, tokens[2], 32);
		    config.mqtt_broker_password[31] = '\0';
		}
		os_sprintf_flash(response, "Broker password set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_access") == 0) {
		config.mqtt_broker_access = atoi(tokens[2]) & (LOCAL_ACCESS | REMOTE_ACCESS);
		os_sprintf_flash(response, "Broker access set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "broker_autoretain") == 0) {
		config.auto_retained = atoi(tokens[2]) != 0;
		os_sprintf_flash(response, "Broker autoretain set\r\n");
		goto command_handled;
	    }
#ifdef BACKLOG
	    if (strcmp(tokens[1], "backlog") == 0) {
		int backlog_size = atoi(tokens[2]);
		if (backlog_size != 0) {
		    if (backlog_buffer != NULL) {
			os_sprintf_flash(response, "Backlog already set\r\n");
			goto command_handled;
		    }
		    backlog_buffer = ringbuf_new(backlog_size);
		    if (backlog_buffer == NULL) {
			os_sprintf(response, "No memory\r\n");
			goto command_handled;
		    }
		    os_sprintf(response, "Backlog set to %d chars\r\n", backlog_size);
		} else {
		    if (backlog_buffer != NULL) {
			ringbuf_free(&backlog_buffer);
		    }
		    os_sprintf_flash(response, "Backlog off\r\n");
		}
		goto command_handled;
	    }
#endif
#ifdef SCRIPTED
	    if (strcmp(tokens[1], "script_logging") == 0) {
		lang_logging = atoi(tokens[2]);
		os_sprintf_flash(response, "Script logging set\r\n");
		goto command_handled;
	    }

	    if (tokens[1][0] == '@') {
		uint32_t slot_no = atoi(&tokens[1][1]);
		if (slot_no == 0 || slot_no > MAX_FLASH_SLOTS) {
		    os_sprintf_flash(response, "Invalid flash slot number");
		} else {
		    slot_no--;
		    uint8_t slots[MAX_FLASH_SLOTS*FLASH_SLOT_LEN];
		    blob_load(VARS_SLOT, (uint32_t *)slots, sizeof(slots));
		    os_strcpy(&slots[slot_no*FLASH_SLOT_LEN], tokens[2]);
		    blob_save(VARS_SLOT, (uint32_t *)slots, sizeof(slots));
		    os_sprintf(response, "%s written to flash\r\n", tokens[1]);
		}
		goto command_handled;
	    }
#ifdef GPIO
#ifdef GPIO_PWM
	    if (strcmp(tokens[1], "pwm_period") == 0) {
		config.pwm_period = atoi(tokens[2]);
		os_sprintf_flash(response, "PWM period set\r\n");
		goto command_handled;
	    }
#endif
#endif
#endif
#ifdef NTP
	    if (strcmp(tokens[1], "ntp_server") == 0) {
		os_strncpy(config.ntp_server, tokens[2], 32);
		config.ntp_server[31] = 0;
		ntp_set_server(config.ntp_server);
		os_sprintf(response, "NTP server set to %s\r\n", config.ntp_server);
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ntp_interval") == 0) {
		config.ntp_interval = atoi(tokens[2]) * 1000000;
		os_sprintf(response, "NTP interval set to %d s\r\n", atoi(tokens[2]));
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ntp_timezone") == 0) {
		config.ntp_timezone = atoi(tokens[2]);
		set_timezone(config.ntp_timezone);
		os_sprintf(response, "NTP timezone set to %d h\r\n", config.ntp_timezone);
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ntp_time") == 0) {
		if (strlen(tokens[2]) != 8 || tokens[2][2] != ':' || tokens[2][5] != ':') {
		    os_sprintf_flash(response, "Time format hh:mm:ss\r\n");
		    goto command_handled;
		}
		tokens[2][2] = '\0';
		tokens[2][5] = '\0';
		set_time_local(atoi(tokens[2]), atoi(&tokens[2][3]), atoi(&tokens[2][6]));
		os_sprintf(response, "Time set to %s \r\n", get_timestr());
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "ntp_weekday") == 0) {
		if (set_weekday_local(tokens[2])) {
		    os_sprintf(response, "Weekday set to %s\r\n", get_weekday());
		} else {
		    os_sprintf_flash(response, "Set weekday failed\r\n");
		}
		goto command_handled;
	    }
#endif
#ifdef MQTT_CLIENT
	    if (strcmp(tokens[1], "mqtt_host") == 0) {
		os_strncpy(config.mqtt_host, tokens[2], 32);
		config.mqtt_host[31] = 0;
		os_sprintf_flash(response, "MQTT host set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "mqtt_port") == 0) {
		config.mqtt_port = atoi(tokens[2]);
		os_sprintf_flash(response, "MQTT port set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "mqtt_ssl") == 0) {
		config.mqtt_ssl = atoi(tokens[2]);
		os_sprintf(response, "MQTT ssl %s\r\n", config.mqtt_ssl?"on":"off");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "mqtt_user") == 0) {
		os_strncpy(config.mqtt_user, tokens[2], 32);
		config.mqtt_user[31] = 0;
		os_sprintf_flash(response, "MQTT user set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "mqtt_password") == 0) {
		os_strncpy(config.mqtt_password, tokens[2], 32);
		config.mqtt_password[31] = 0;
		os_sprintf_flash(response, "MQTT password set\r\n");
		goto command_handled;
	    }

	    if (strcmp(tokens[1], "mqtt_id") == 0) {
		os_strncpy(config.mqtt_id, tokens[2], 32);
		config.mqtt_id[31] = 0;
		os_sprintf_flash(response, "MQTT id set\r\n");
		goto command_handled;
	    }
#endif				/* MQTT_CLIENT */
	}

    }

    /* Control comes here only if the tokens[0] command is not handled */
    os_sprintf_flash(response, "\r\nInvalid Command\r\n");

 command_handled:
    to_console(response);
 command_handled_2:
    system_os_post(user_procTaskPrio, SIG_CONSOLE_TX, (ETSParam) pespconn);
    return;
}
