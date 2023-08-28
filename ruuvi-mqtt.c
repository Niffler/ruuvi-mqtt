// Copyright (c) 2023 Niffler
// Copyright (c) 2021 David G. Young
// Copyright (c) 2015 Damian Kołakowski. All rights reserved.

// cc ruuvi-mqtt.c -lbluetooth -lpaho-mqtt3c -o ruuvi-mqtto

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>
#include <MQTTClient.h>

#define ADDRESS "tcp://localhost:1883"
#define CLIENTID "Ruuvi Bridge"
#define TOPIC "ruuvi"
#define QOS 1
#define TIMEOUT 10000L

typedef struct ruuvi_data
{
    char *addr;
    int16_t temperature;
    uint16_t humidity;
    uint16_t pressure;
} ruuvi_data;

int device;
MQTTClient client;

struct hci_request ble_hci_request(uint16_t ocf, int clen, void *status, void *cparam)
{
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = ocf;
    rq.cparam = cparam;
    rq.clen = clen;
    rq.rparam = status;
    rq.rlen = 1;
    return rq;
}

// cleanup and exit the program with exit code 0
void exit_clean()
{
    int ret, status;

    // Disable scanning.

    le_set_scan_enable_cp scan_cp;
    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = 0x00; // Disable flag.

    struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
    ret = hci_send_req(device, &disable_adv_rq, 1000);
    if (ret < 0)
        perror("Failed to disable scan.");

    hci_close_dev(device);

    // Close mqtt connection

    int rc;
    if ((rc = MQTTClient_disconnect(client, 10000)) != MQTTCLIENT_SUCCESS)
        printf("Failed to disconnect, return code %d\n", rc);
    MQTTClient_destroy(&client);

    exit(0);
}

// handles timeout
void signal_handler(int s)
{
    printf("received SIGALRM\n");
    exit_clean();
}

int ruuvi_data_to_json(size_t len, char json_string[len], ruuvi_data data)
{
    return snprintf(json_string, 512, "{\"MAC\":\"%s\",\"temperature\":%hd,\"humidity\":%hu,\"pressure\":%hu}", data.addr, data.temperature, data.humidity, data.pressure);
}

void publish_ruuvi_data(MQTTClient_message *message, MQTTClient_deliveryToken *token, ruuvi_data data)
{
    char json_payload[512];
    int rc = ruuvi_data_to_json(512, json_payload, data);
    message->payload = json_payload;
    message->payloadlen = (int)strlen(json_payload);
    message->qos = QOS;
    message->retained = 0;

    if ((rc = MQTTClient_publishMessage(client, TOPIC, message, token)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to publish message, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }
}

int main()
{
    // MQTT variables
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    int rc;

    // BLE variables
    int ret, status;

    // Create MQTT client

    if ((rc = MQTTClient_create(&client, ADDRESS, CLIENTID,
                                MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to create client, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Connect to MQTT server

    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    // Get HCI device.

    device = hci_open_dev(1);
    if (device < 0)
    {
        device = hci_open_dev(0);
        if (device >= 0)
        {
            printf("Using hci0\n");
        }
    }
    else
    {
        printf("Using hci1\n");
    }

    if (device < 0)
    {
        perror("Failed to open HCI device.");
        return 0;
    }

    // Set BLE scan parameters.

    le_set_scan_parameters_cp scan_params_cp;
    memset(&scan_params_cp, 0, sizeof(scan_params_cp));
    scan_params_cp.type = 0x00;
    scan_params_cp.interval = htobs(0x0010);
    scan_params_cp.window = htobs(0x0010);
    scan_params_cp.own_bdaddr_type = 0x00; // Public Device Address (default).
    scan_params_cp.filter = 0x00;          // Accept all.

    struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);

    ret = hci_send_req(device, &scan_params_rq, 1000);
    if (ret < 0)
    {
        hci_close_dev(device);
        perror("Failed to set scan parameters data.");
        return 0;
    }

    // Set BLE events report mask.

    le_set_event_mask_cp event_mask_cp;
    memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
    int i = 0;
    for (i = 0; i < 8; i++)
        event_mask_cp.mask[i] = 0xFF;

    struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
    ret = hci_send_req(device, &set_mask_rq, 1000);
    if (ret < 0)
    {
        hci_close_dev(device);
        perror("Failed to set event mask.");
        return 0;
    }

    // Enable scanning.

    le_set_scan_enable_cp scan_cp;
    memset(&scan_cp, 0, sizeof(scan_cp));
    scan_cp.enable = 0x01;     // Enable flag.
    scan_cp.filter_dup = 0x00; // Filtering disabled.

    struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

    ret = hci_send_req(device, &enable_adv_rq, 1000);
    if (ret < 0)
    {
        hci_close_dev(device);
        perror("Failed to enable scan.");
        return 0;
    }

    // Get Results.

    struct hci_filter nf;
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
    {
        hci_close_dev(device);
        perror("Could not set socket options\n");
        return 0;
    }

    uint8_t buf[HCI_MAX_EVENT_SIZE];
    evt_le_meta_event *meta_event;
    le_advertising_info *info;
    int len;
    int count = 0;

    const int timeout = 10;
    const int reset_timeout = 1; // wether to reset the timer on a received scan event (continuous scanning)
    const int max_count = 1000;

    // Install a signal handler so that we can set the exit code and clean up
    if (signal(SIGALRM, signal_handler) == SIG_ERR)
    {
        hci_close_dev(device);
        perror("Could not install signal handler\n");
        return 0;
    }

    if (timeout > 0)
        alarm(timeout); // set the alarm timer, when time is up the program will be terminated

    sigset_t sigalrm_set; // apparently the signal must be unblocked in some cases
    sigemptyset(&sigalrm_set);
    sigaddset(&sigalrm_set, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &sigalrm_set, NULL) != 0)
    {
        hci_close_dev(device);
        perror("Could not unblock alarm signal");
        return 0;
    }

    // Keep scanning until the timeout is triggered. Then exit.
    while (1)
    {
        len = read(device, buf, sizeof(buf));
        if (len >= HCI_EVENT_HDR_SIZE)
        {
            meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
            if (meta_event->subevent == EVT_LE_ADVERTISING_REPORT)
            {
                count++;
                if (reset_timeout != 0 && timeout > 0) // reset/restart the alarm timer
                    alarm(timeout);

                // print results
                uint8_t reports_count = meta_event->data[0];
                void *offset = meta_event->data + 1;
                while (reports_count--)
                {
                    info = (le_advertising_info *)offset;

                    // filter for ruuvi advertisements
                    // Manufacturer ID, least significant byte first: 0x0499 = Ruuvi Innovations Ltd
                    if (info->data[5] == 0x99 && info->data[6] == 0x04)
                    {
                        char addr[18];
                        ba2str(&(info->bdaddr), addr);
                        printf("%s %d", addr, (int8_t)info->data[info->length]);

                        int16_t temp_raw = (info->data[8] << 8) + info->data[9];
                        double temp = temp_raw * 0.005;
                        printf(" temp: %.2f", temp);

                        uint16_t hum_raw = (info->data[10] << 8) + info->data[11];
                        double hum = hum_raw * 0.0025;
                        printf(" hum: %.2f", hum);

                        uint16_t pres_raw = (info->data[12] << 8) + info->data[13];
                        double pres = (pres_raw + 50000) / 100.0;
                        printf(" pres: %.2f", pres);
                        printf("\n");

                        // TODO: parse payload further: accel, power, movement, ...

                        ruuvi_data data = {.addr = addr, .temperature = temp_raw, .humidity = hum_raw, .pressure = pres_raw};
                        publish_ruuvi_data(&pubmsg, &token, data);
                    }
                    offset = info->data + info->length + 2;
                }
            }
        }
    }

    // Prevent SIGALARM from firing during the clean up procedure
    if (sigprocmask(SIG_BLOCK, &sigalrm_set, NULL) != 0)
    {
        hci_close_dev(device);
        perror("Could not block alarm signal");
        return 0;
    }

    exit_clean();
    return 0;
}