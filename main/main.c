#ifdef ESP_AP_CONNECT
    #define WIFI_SSID "ESP32_wifi"
    #define WIFI_PASSWORD "esp32pass"
    #define OPPONENT_UDP_PORT 5004
    #define SET_IPADDR4(ipAddr) \
        IP_ADDR4((ipAddr), 192, 168, 4, 255);
#else
    #define WIFI_SSID "WX03_Todoroki"
    #define WIFI_PASSWORD "TodorokiWX03"
    #define OPPONENT_UDP_PORT 50505
    #define SET_IPADDR4(ipAddr) \
        IP_ADDR4((ipAddr), 192, 168, 179, 6);
#endif

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "stdio.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>  // Boolean

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"

#define UDP_PAYLOAD_SIZE 50

/* --- PRINTF_BYTE_TO_BINARY macro's --- */
#define PRINTF_BINARY_SEPARATOR
#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c%c%c"
#define PRINTF_BYTE_TO_BINARY_INT8(i) \
    (((i)&0x80ll) ? '1' : '0'),       \
        (((i)&0x40ll) ? '1' : '0'),   \
        (((i)&0x20ll) ? '1' : '0'),   \
        (((i)&0x10ll) ? '1' : '0'),   \
        (((i)&0x08ll) ? '1' : '0'),   \
        (((i)&0x04ll) ? '1' : '0'),   \
        (((i)&0x02ll) ? '1' : '0'),   \
        (((i)&0x01ll) ? '1' : '0')

#define PRINTF_BINARY_PATTERN_INT16 \
    PRINTF_BINARY_PATTERN_INT8 PRINTF_BINARY_SEPARATOR PRINTF_BINARY_PATTERN_INT8
#define PRINTF_BYTE_TO_BINARY_INT16(i) \
    PRINTF_BYTE_TO_BINARY_INT8((i) >> 8), PRINTF_BYTE_TO_BINARY_INT8(i)
#define PRINTF_BINARY_PATTERN_INT32 \
    PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_SEPARATOR PRINTF_BINARY_PATTERN_INT16
#define PRINTF_BYTE_TO_BINARY_INT32(i) \
    PRINTF_BYTE_TO_BINARY_INT16((i) >> 16), PRINTF_BYTE_TO_BINARY_INT16(i)
#define PRINTF_BINARY_PATTERN_INT64 \
    PRINTF_BINARY_PATTERN_INT32 PRINTF_BINARY_SEPARATOR PRINTF_BINARY_PATTERN_INT32
#define PRINTF_BYTE_TO_BINARY_INT64(i) \
    PRINTF_BYTE_TO_BINARY_INT32((i) >> 32), PRINTF_BYTE_TO_BINARY_INT32(i)
/* --- end macros --- */

static const char *TAG = "MyModule";

esp_err_t event_handler(void *ctx, system_event_t *event)
{
    return ESP_OK;
}

void esp32setup()
{
    nvs_flash_init();
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
}

void esp32connectToWiFi()
{
    bool wifiConnected = false;

    wifi_config_t sta_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
            .bssid_set = false}};
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());

    ESP_LOGI(TAG, "Connecting to wifi: %s", WIFI_SSID);

    while( !wifiConnected ) {
        wifiConnected = esp_wifi_connect();

        // wait until wifi connects
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    };

    ESP_LOGI(TAG, "wifi connect is %d", wifiConnected);
    ESP_LOGI(TAG, "-> Connected to: %s", WIFI_SSID);
}

unsigned int microsFromStart()
{
    return (unsigned int) esp_timer_get_time();
}

typedef struct _octet
{
    union {
        char val;
        struct
        {
            unsigned h : 1;
            unsigned g : 1;
            unsigned f : 1;
            unsigned e : 1;
            unsigned d : 1;
            unsigned c : 1;
            unsigned b : 1;
            unsigned a : 1;
        };
    };
} octet;

octet create_octet(bool *bits) // assure length is 8..
{
    octet o;
    o.a = bits[0];
    o.b = bits[1];
    o.c = bits[2];
    o.d = bits[3];
    o.e = bits[4];
    o.f = bits[5];
    o.g = bits[6];
    o.h = bits[7];
    return o;
}

typedef struct _aes67 {
    const unsigned int bits;
    const unsigned int numberOfSamples;
    const char * packetTemplate;
    unsigned short sequenceNumber;
    unsigned int timestamp;
    unsigned int ssrcIdentifier;
    const unsigned int maxPayloadCount;
    const unsigned int totalBits; // maximum.
    unsigned short * payloadElements;
    char * payload;
    const char * payloadTemplate;
    unsigned int payloadOctetsCount;
    unsigned int currentPayloadCount;
} AES67;

AES67 * aes67_l16_48khz_from_scratch(
    unsigned short sequenceNumber,
    unsigned int timestamp,
    unsigned int ssrcIdentifier
)
{
    const unsigned int sampleSize = 12;
    const unsigned int bits = 16;
    unsigned int totalBits = 32 * 3 + bits * sampleSize; // 288 bits of boolean

    AES67 *aes67 = malloc(sizeof(AES67));
    AES67 _aes67 = {
        bits,
        sampleSize,
        "1000000000001011" PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT32 PRINTF_BINARY_PATTERN_INT32 "%s",
        sequenceNumber,
        timestamp,
        ssrcIdentifier,
        sampleSize,
        totalBits,
        (unsigned short *)calloc(sampleSize, sizeof(unsigned short)),
        (char *)calloc(sampleSize * bits + 10, sizeof(char)),
        PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16 PRINTF_BINARY_PATTERN_INT16,
        0,
        0
    };
    memcpy(aes67, &_aes67, sizeof(AES67));
    return aes67;
}

void aes67renewal(AES67 * aes67, unsigned int timestamp) {
    aes67->timestamp = timestamp;
    free(aes67->payloadElements);
    free(aes67->payload);
    aes67->payloadElements = (unsigned short *)calloc(aes67->numberOfSamples, sizeof(unsigned short));
    aes67->payload = (char *)calloc(aes67->numberOfSamples * aes67->bits + 10, sizeof(char));
    aes67->payloadOctetsCount = 0;
    aes67->currentPayloadCount = 0;
}

void aes67createPayloadString(AES67 * aes67) {
    snprintf(
        aes67->payload,
        aes67->numberOfSamples * aes67->bits + 1,
        aes67->payloadTemplate,
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[0]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[1]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[2]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[3]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[4]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[5]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[6]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[7]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[8]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[9]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[10]),
        PRINTF_BYTE_TO_BINARY_INT16(aes67->payloadElements[11])   // 12
    );
    aes67->currentPayloadCount = 12;
}

void aes67createSamplePayload(AES67 * aes67, unsigned int sample) {
    for (int i = 0; i < aes67->numberOfSamples; i++) {
        aes67->payloadElements[i] = sample;
    };
}

// string must be bigger than totalBits + 1
void writeAES67toString(char * str, AES67 * aes67)
{
    aes67createPayloadString(aes67);
    snprintf(
        // overwrite given string
        str,
        aes67->totalBits + 1,
        // template
        aes67->packetTemplate,
        // values
        PRINTF_BYTE_TO_BINARY_INT16(aes67->sequenceNumber),
        PRINTF_BYTE_TO_BINARY_INT32(aes67->timestamp),
        PRINTF_BYTE_TO_BINARY_INT32(aes67->ssrcIdentifier),
        aes67->payload
    );
}

void writeAES67toBinary(bool * binary, AES67 * aes67)
{
    char str[aes67->totalBits + 1]; // last char is 0
    writeAES67toString(str, aes67);

    for (unsigned int i = 0; i < aes67->totalBits; i++)
    {
        binary[i] = str[i] - '0';   // assuming that all chars are '1' or '0'
    };
}

char * aes67toHexArray(char * hex, AES67 * aes67)
{
    bool binary[aes67->totalBits]; // don't need last 0
    writeAES67toBinary(binary, aes67);
    unsigned int numberOfOctets = aes67->totalBits / 8 + (aes67->totalBits % 8 != 0);  // if not 8N, it ceils up the number
    // char * hex = (char *)calloc(numberOfOctets, sizeof(char));  // NOT need the last 0

    for (unsigned int i = 0; i < numberOfOctets; i++)
    {
        bool tmp_bins[] = {
            binary[i * 8 + 0],
            binary[i * 8 + 1],
            binary[i * 8 + 2],
            binary[i * 8 + 3],
            binary[i * 8 + 4],
            binary[i * 8 + 5],
            binary[i * 8 + 6],
            binary[i * 8 + 7]           // need update; consider out of bounds
        };
        hex[i] = create_octet(tmp_bins).val;  // inserts a char
    }

    aes67->payloadOctetsCount = numberOfOctets;

    return hex;
}

void app_main(void)
{
    esp32setup();
    esp32connectToWiFi();

    unsigned int count = 0;

    // UDP inits
    struct udp_pcb * udp;
    struct pbuf *p;
    ip_addr_t ipAddr;
    err_t err;
    SET_IPADDR4(&ipAddr);
    udp = udp_new();
    err = udp_connect(udp, &ipAddr, OPPONENT_UDP_PORT);

    // payload string buffer
    char payload[UDP_PAYLOAD_SIZE];
    memset(payload, 0, UDP_PAYLOAD_SIZE);

    AES67 * aes67 = aes67_l16_48khz_from_scratch(50, microsFromStart(), 52);

    unsigned int numberOfOctets = aes67->totalBits / 8 + (aes67->totalBits % 8 != 0);
    char *hex = (char *)calloc(numberOfOctets, sizeof(char));

    aes67createSamplePayload(aes67, count);
    aes67toHexArray(hex, aes67);
    
    p = pbuf_alloc(PBUF_TRANSPORT, aes67->payloadOctetsCount, PBUF_RAM);
    memcpy(p->payload, hex, aes67->payloadOctetsCount);

    // Presend packet. No need
    /* 
        err = udp_send(udp, p);
        // udp_send(udp, p);

        if (err != 0)
        {
            ESP_LOGI(TAG, "err is %d", err);
        };
        // free(p);
    */

    // Send packets
    while (true)
    {
        count++;

        // renew AES67 struct
        aes67renewal(aes67, microsFromStart());
        aes67createSamplePayload(aes67, count);
        aes67toHexArray(hex, aes67);

        // pbuf_realloc(p, aes67->payloadOctetsCount);
        // p = pbuf_alloc(PBUF_TRANSPORT, aes67->payloadOctetsCount, PBUF_RAM);
        memcpy(p->payload, hex, aes67->payloadOctetsCount);

        // ESP_LOGI(TAG, "No. %d at %u, octetSize: %u", count, microsFromStart(), aes67->payloadOctetsCount);

        err = udp_send(udp, p);
        // udp_send(udp, p);

        if (err != 0) {
            ESP_LOGI(TAG, "%d - err is %d", count, err);
        };

        vTaskDelay(1);
    };
    pbuf_free(p);

    while (true) {
        vTaskDelay(1000);
    };
}
