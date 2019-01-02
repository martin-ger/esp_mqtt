#include "user_interface.h"
#include "config_flash.h"

/*     From the document 99A-SDK-Espressif IOT Flash RW Operation_v0.2      *
 * -------------------------------------------------------------------------*
 * Flash is erased sector by sector, which means it has to erase 4Kbytes one
 * time at least. When you want to change some data in flash, you have to
 * erase the whole sector, and then write it back with the new data.
 *--------------------------------------------------------------------------*/
void ICACHE_FLASH_ATTR config_load_default(sysconfig_p config) {
    uint8_t mac[6];

    os_memset(config, 0, sizeof(sysconfig_t));
    os_printf("Loading default configuration\r\n");
    config->magic_number = MAGIC_NUMBER;
    config->length = sizeof(sysconfig_t);
    os_sprintf(config->ssid, "%s", WIFI_SSID);
    os_sprintf(config->password, "%s", WIFI_PASSWORD);
    config->auto_connect = 0;
    os_sprintf(config->ap_ssid, "%s", WIFI_AP_SSID);
    os_sprintf(config->ap_password, "%s", WIFI_AP_PASSWORD);
    config->ap_open = 1;
    config->ap_on = 1;

    config->locked = 0;
    config->lock_password[0] = '\0';

    IP4_ADDR(&config->network_addr, 192, 168, 4, 1);
    config->dns_addr.addr = 0;	// use DHCP
    config->my_addr.addr = 0;	// use DHCP   
    config->my_netmask.addr = 0;	// use DHCP   
    config->my_gw.addr = 0;	// use DHCP

    config->system_output = SYSTEM_OUTPUT_INFO;
    config->bit_rate = 115200;  

    config->mdns_mode = 0;	// no mDNS

    config->clock_speed = 80;
    config->config_port = CONSOLE_SERVER_PORT;
    config->config_access = LOCAL_ACCESS | REMOTE_ACCESS;

    config->mqtt_broker_port = MQTT_PORT;
    config->max_subscriptions = 30;
    config->max_retained_messages = 30;
    config->max_clients = 0;
    config->auto_retained = 0;
    os_sprintf(config->mqtt_broker_user, "%s", "none");
    config->mqtt_broker_password[0] = 0;
    config->mqtt_broker_access = LOCAL_ACCESS | REMOTE_ACCESS;

#ifdef MQTT_CLIENT
    os_sprintf(config->mqtt_host, "%s", "none");
    config->mqtt_port = 1883;
    config->mqtt_ssl = false;
    os_sprintf(config->mqtt_user, "%s", "none");
    config->mqtt_password[0] = 0;
    wifi_get_macaddr(0, mac);
    os_sprintf(config->mqtt_id, "%s_%02x%02x%02x", MQTT_ID, mac[3], mac[4], mac[5]);
#endif
#ifdef NTP
    os_sprintf(config->ntp_server, "%s", "1.pool.ntp.org");
    config->ntp_interval = 300000000;
    config->ntp_timezone = 0;
#endif
#ifdef DNS_RESP
    os_sprintf(config->broker_dns_name, "%s", "none");
#endif
#ifdef GPIO
#ifdef GPIO_PWM
    config->pwm_period = 5000;
#endif
#endif
}

int ICACHE_FLASH_ATTR config_load(sysconfig_p config) {
    if (config == NULL)
	return -1;
    uint16_t base_address = FLASH_BLOCK_NO;

    spi_flash_read(base_address * SPI_FLASH_SEC_SIZE, &config->magic_number, 4);

    if ((config->magic_number != MAGIC_NUMBER)) {
	os_printf("\r\nNo config found, saving default in flash\r\n");
	config_load_default(config);
	config_save(config);
	return -1;
    }

    os_printf("\r\nConfig found and loaded\r\n");    
    spi_flash_read(base_address * SPI_FLASH_SEC_SIZE, (uint32 *) config, sizeof(sysconfig_t));
    if (config->length != sizeof(sysconfig_t)) {
        os_printf("Length Mismatch, probably old version of config, loading defaults\r\n");
        config_load_default(config);
        config_save(config);
        return -1;
    }
    return 0;
}

void ICACHE_FLASH_ATTR config_save(sysconfig_p config) {
    uint16_t base_address = FLASH_BLOCK_NO;
    os_printf("Saving configuration\r\n");
    spi_flash_erase_sector(base_address);
    spi_flash_write(base_address * SPI_FLASH_SEC_SIZE, (uint32 *) config, sizeof(sysconfig_t));
}

void ICACHE_FLASH_ATTR blob_save(uint8_t blob_no, uint32_t * data, uint16_t len) {
    uint16_t base_address = FLASH_BLOCK_NO + 1 + blob_no;
    spi_flash_erase_sector(base_address);
    spi_flash_write(base_address * SPI_FLASH_SEC_SIZE, data, len);
}

void ICACHE_FLASH_ATTR blob_load(uint8_t blob_no, uint32_t * data, uint16_t len) {
    uint16_t base_address = FLASH_BLOCK_NO + 1 + blob_no;
    spi_flash_read(base_address * SPI_FLASH_SEC_SIZE, data, len);
}

void ICACHE_FLASH_ATTR blob_zero(uint8_t blob_no, uint16_t len) {
    int i;
    uint8_t z[len];
    os_memset(z, 0, len);
    uint16_t base_address = FLASH_BLOCK_NO + 1 + blob_no;
    spi_flash_erase_sector(base_address);
    spi_flash_write(base_address * SPI_FLASH_SEC_SIZE, (uint32_t *) z, len);
}

const uint8_t esp_init_data_default[] = {
    "\x05\x08\x04\x02\x05\x05\x05\x02\x05\x00\x04\x05\x05\x04\x05\x05"
    "\x04\xFE\xFD\xFF\xF0\xF0\xF0\xE0\xE0\xE0\xE1\x0A\xFF\xFF\xF8\x00"
    "\xF8\xF8\x4E\x4A\x46\x40\x3C\x38\x00\x00\x01\x01\x02\x03\x04\x05"
    "\x01\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\xE1\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x01\x93\x43\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"};

void user_rf_pre_init() {
  uint8_t esp_init_data_current[sizeof(esp_init_data_default)];

  enum flash_size_map size_map = system_get_flash_size_map();
  uint32 rf_cal_sec = 0, addr, i;
  //os_printf("\nUser preinit: ");
   switch (size_map) {
      case FLASH_SIZE_4M_MAP_256_256:
         rf_cal_sec = 128 - 5;     
         break;

      case FLASH_SIZE_8M_MAP_512_512:
         rf_cal_sec = 256 - 5;
         break;

      case FLASH_SIZE_16M_MAP_512_512:
      case FLASH_SIZE_16M_MAP_1024_1024:
         rf_cal_sec = 512 - 5;
         break;

      case FLASH_SIZE_32M_MAP_512_512:
      case FLASH_SIZE_32M_MAP_1024_1024:
         rf_cal_sec = 1024 - 5;
         break;

      default:
         rf_cal_sec = 0;
         break;
   }

  addr = ((rf_cal_sec) * SPI_FLASH_SEC_SIZE)+SPI_FLASH_SEC_SIZE;
  spi_flash_read(addr, (uint32_t *)esp_init_data_current, sizeof(esp_init_data_current));

  for (i=0; i<sizeof(esp_init_data_default); i++) {
    
    if (esp_init_data_current[i] != esp_init_data_default[i]) {     
      spi_flash_erase_sector(rf_cal_sec);
      spi_flash_erase_sector(rf_cal_sec+1);
      spi_flash_erase_sector(rf_cal_sec+2);
      addr = ((rf_cal_sec) * SPI_FLASH_SEC_SIZE)+SPI_FLASH_SEC_SIZE;
      os_printf("Storing rfcal init data @ address=0x%08X\n", addr);
      spi_flash_write(addr, (uint32 *)esp_init_data_default, sizeof(esp_init_data_default));
     
      break;
    }
/* else {
      os_printf("RF data[%u] is ok\n", i);
    }*/
  }
}
