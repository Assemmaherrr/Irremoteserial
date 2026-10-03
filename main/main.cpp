#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_nimble_hci.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs_flash.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "IRrecv.h"
#include "IRremoteESP8266.h"
#include "IRutils.h"

static const char *TAG = "c3_ir_analyzer";

static constexpr char kDeviceName[] = "C3-IR-ANALYZER";
static constexpr uint16_t kRecvPin = 10;
static constexpr uint16_t kCaptureBufferSize = 1024;
static constexpr uint8_t kTimeoutMs = 50;
static constexpr uint16_t kMinUnknownSize = 12;
static constexpr size_t kBleChunkSize = 200;
static constexpr size_t kMessageBufferSize = 2048;

static const ble_uuid128_t kNusServiceUuid =
    BLE_UUID128_INIT(0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
                     0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E);
static const ble_uuid128_t kNusTxUuid =
    BLE_UUID128_INIT(0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
                     0x93, 0xF3, 0xA3, 0xB5, 0x03, 0x00, 0x40, 0x6E);

static std::atomic<bool> ble_connected{false};
static std::atomic<uint16_t> ble_conn_handle{BLE_HS_CONN_HANDLE_NONE};
static uint16_t nus_tx_value_handle = 0;

static IRrecv irrecv(kRecvPin, kCaptureBufferSize, kTimeoutMs, true);
static decode_results results;

#ifndef ble_gattc_notify_custom
#define ble_gattc_notify_custom ble_gatts_notify_custom
#endif

static int ble_gap_event_handler(ble_gap_event *event, void *arg);
static void ble_advertise(void);
static ble_gatt_chr_def nus_characteristics[] = {
    {
        .uuid = &kNusTxUuid.u,
        .access_cb = nullptr,
        .flags = BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &nus_tx_value_handle,
    },
    {
        0,
    },
};

static const ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &kNusServiceUuid.u,
        .characteristics = nus_characteristics,
    },
    {
        0,
    },
};

static void ble_send_text(const char *text, size_t length) {
  if (text == nullptr || length == 0 || !ble_connected.load()) return;

  size_t offset = 0;
  while (offset < length && ble_connected.load()) {
    const size_t chunk_len = std::min(kBleChunkSize, length - offset);
    struct os_mbuf *om = ble_hs_mbuf_from_flat(text + offset, chunk_len);
    if (om == nullptr) {
      ESP_LOGE(TAG, "BLE mbuf allocation failed");
      return;
    }

    const int rc =
        ble_gattc_notify_custom(ble_conn_handle.load(), nus_tx_value_handle, om);
    if (rc != 0) {
      ESP_LOGW(TAG, "BLE notify failed: rc=%d", rc);
      os_mbuf_free_chain(om);
      return;
    }
    offset += chunk_len;
  }
}

static void ir_receiver_task(void *arg) {
#if DECODE_HASH
  irrecv.setUnknownThreshold(kMinUnknownSize);
#endif
  irrecv.setTolerance(kTolerance);
  irrecv.enableIRIn();
  ESP_LOGI(TAG, "IR receiver listening on GPIO %u", kRecvPin);

  char out[kMessageBufferSize];
  while (true) {
    if (irrecv.decode(&results)) {
      if (results.overflow) {
        ESP_LOGW(TAG, "Capture buffer overflow; increase size");
      }

      const String basic = resultToHumanReadableBasic(&results);
      const String source = resultToSourceCode(&results);
      const String protocol = typeToString(results.decode_type, false);

      const int written = snprintf(
          out, sizeof(out),
          "Protocol: %s\n"
          "Hex: 0x%llX\n"
          "Address: 0x%X\n"
          "Command: 0x%X\n"
          "Bits: %u\n"
          "Basic: %s\n"
          "Source: %s\n"
          "------------------------------\n",
          protocol.c_str(), static_cast<unsigned long long>(results.value),
          static_cast<unsigned int>(results.address),
          static_cast<unsigned int>(results.command),
          static_cast<unsigned int>(results.bits), basic.c_str(), source.c_str());

      if (written > 0) {
        const size_t out_len = std::min(static_cast<size_t>(written), sizeof(out) - 1);
        printf("%s", out);
        fflush(stdout);
        ble_send_text(out, out_len);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

static void ble_on_sync(void) {
  uint8_t addr_val[6] = {0};
  int rc = ble_hs_id_infer_auto(0, nullptr);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: rc=%d", rc);
    return;
  }

  rc = ble_hs_id_copy_addr(BLE_ADDR_PUBLIC, addr_val, nullptr);
  if (rc != 0) {
    ESP_LOGW(TAG, "ble_hs_id_copy_addr failed: rc=%d", rc);
  }

  ble_advertise();
}

static void ble_host_task(void *param) { nimble_port_run(); }

static int ble_gap_event_handler(ble_gap_event *event, void *arg) {
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      if (event->connect.status == 0) {
        ble_conn_handle.store(event->connect.conn_handle);
        ble_connected.store(true);
        ESP_LOGI(TAG, "BLE central connected (handle=%u)", ble_conn_handle.load());
      } else {
        ble_connected.store(false);
        ble_conn_handle.store(BLE_HS_CONN_HANDLE_NONE);
        ESP_LOGW(TAG, "BLE connect failed; restarting advertising");
        ble_advertise();
      }
      return 0;

    case BLE_GAP_EVENT_DISCONNECT:
      ble_connected.store(false);
      ble_conn_handle.store(BLE_HS_CONN_HANDLE_NONE);
      ESP_LOGI(TAG, "BLE central disconnected; restarting advertising");
      ble_advertise();
      return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
      ESP_LOGI(TAG, "Advertising complete; restarting");
      ble_advertise();
      return 0;

    default:
      return 0;
  }
}

static void ble_advertise(void) {
  ble_gap_adv_params adv_params = {};
  adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

  ble_hs_adv_fields fields = {};
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  fields.tx_pwr_lvl_is_present = 1;
  fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;
  fields.name = reinterpret_cast<const uint8_t *>(kDeviceName);
  fields.name_len = strlen(kDeviceName);
  fields.name_is_complete = 1;

  int rc = ble_gap_adv_set_fields(&fields);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: rc=%d", rc);
    return;
  }

  rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, nullptr, BLE_HS_FOREVER, &adv_params,
                         ble_gap_event_handler, nullptr);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_start failed: rc=%d", rc);
  }
}

static void ble_init(void) {
  int rc = nvs_flash_init();
  if (rc == ESP_ERR_NVS_NO_FREE_PAGES || rc == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    rc = nvs_flash_init();
  }
  ESP_ERROR_CHECK(rc);

  ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());
  nimble_port_init();

  ble_hs_cfg.sync_cb = ble_on_sync;
  ble_svc_gap_init();
  ble_svc_gatt_init();

  rc = ble_svc_gap_device_name_set(kDeviceName);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_svc_gap_device_name_set failed: rc=%d", rc);
  }

  rc = ble_gatts_count_cfg(gatt_svcs);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gatts_count_cfg failed: rc=%d", rc);
  }

  rc = ble_gatts_add_svcs(gatt_svcs);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gatts_add_svcs failed: rc=%d", rc);
  }

  nimble_port_freertos_init(ble_host_task);
}

extern "C" void app_main(void) {
  ble_init();

  xTaskCreatePinnedToCore(ir_receiver_task, "ir_receiver_task", 8192, nullptr, 5,
                          nullptr, 0);
}
