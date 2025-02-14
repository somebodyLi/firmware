/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "blake2s.h"
#include "br_check.h"
#include "common.h"
#include "device.h"
#include "flash.h"
#include "image.h"
#include "sdram.h"
#include "se_atca.h"
#include "secbool.h"
#include "usb.h"
#include "version.h"

#include "bootui.h"
#include "messages.h"

#include "memzero.h"

#include "ble.h"
#include "bootui.h"
#include "nordic_dfu.h"
#include "spi.h"

#define MSG_HEADER1_LEN 9
#define MSG_HEADER2_LEN 1

#define UPDATE_BLE 0x5A
#define UPDATE_ST 0x55

static uint8_t update_mode = 0;

#define BLE_INIT_DATA_LEN 512

secbool msg_parse_header(const uint8_t *buf, uint16_t *msg_id,
                         uint32_t *msg_size) {
  if (buf[0] != '?' || buf[1] != '#' || buf[2] != '#') {
    return secfalse;
  }
  *msg_id = (buf[3] << 8) + buf[4];
  *msg_size = (buf[5] << 24) + (buf[6] << 16) + (buf[7] << 8) + buf[8];
  return sectrue;
}

typedef struct {
  uint8_t iface_num;
  uint8_t packet_index;
  uint8_t packet_pos;
  uint8_t buf[USB_PACKET_SIZE];
} usb_write_state;

/* we don't use secbool/sectrue/secfalse here as it is a nanopb api */
static bool _usb_write(pb_ostream_t *stream, const pb_byte_t *buf,
                       size_t count) {
  usb_write_state *state = (usb_write_state *)(stream->state);

  size_t written = 0;
  // while we have data left
  while (written < count) {
    size_t remaining = count - written;
    // if all remaining data fit into our packet
    if (state->packet_pos + remaining <= USB_PACKET_SIZE) {
      // append data from buf to state->buf
      memcpy(state->buf + state->packet_pos, buf + written, remaining);
      // advance position
      state->packet_pos += remaining;
      // and return
      return true;
    } else {
      // append data that fits
      memcpy(state->buf + state->packet_pos, buf + written,
             USB_PACKET_SIZE - state->packet_pos);
      written += USB_PACKET_SIZE - state->packet_pos;
      // send packet
      int r;
      if (host_channel == CHANNEL_USB) {
        r = usb_webusb_write_blocking(state->iface_num, state->buf,
                                      USB_PACKET_SIZE, USB_TIMEOUT);
      } else {
        hal_delay(5);
        r = spi_slave_send(state->buf, USB_PACKET_SIZE, USB_TIMEOUT);
      }
      ensure(sectrue * (r == USB_PACKET_SIZE), NULL);
      // prepare new packet
      state->packet_index++;
      memzero(state->buf, USB_PACKET_SIZE);
      state->buf[0] = '?';
      state->packet_pos = MSG_HEADER2_LEN;
    }
  }

  return true;
}

static void _usb_write_flush(usb_write_state *state) {
  // if packet is not filled up completely
  if (state->packet_pos < USB_PACKET_SIZE) {
    // pad it with zeroes
    memzero(state->buf + state->packet_pos,
            USB_PACKET_SIZE - state->packet_pos);
  }
  // send packet
  int r;
  if (host_channel == CHANNEL_USB) {
    r = usb_webusb_write_blocking(state->iface_num, state->buf, USB_PACKET_SIZE,
                                  USB_TIMEOUT);
  } else {
    hal_delay(5);
    r = spi_slave_send(state->buf, USB_PACKET_SIZE, USB_TIMEOUT);
  }
  ensure(sectrue * (r == USB_PACKET_SIZE), NULL);
}

static secbool _send_msg(uint8_t iface_num, uint16_t msg_id,
                         const pb_msgdesc_t *fields, const void *msg) {
  // determine message size by serializing it into a dummy stream
  pb_ostream_t sizestream = {.callback = NULL,
                             .state = NULL,
                             .max_size = SIZE_MAX,
                             .bytes_written = 0,
                             .errmsg = NULL};
  if (false == pb_encode(&sizestream, fields, msg)) {
    return secfalse;
  }
  const uint32_t msg_size = sizestream.bytes_written;

  usb_write_state state = {
      .iface_num = iface_num,
      .packet_index = 0,
      .packet_pos = MSG_HEADER1_LEN,
      .buf =
          {
              '?',
              '#',
              '#',
              (msg_id >> 8) & 0xFF,
              msg_id & 0xFF,
              (msg_size >> 24) & 0xFF,
              (msg_size >> 16) & 0xFF,
              (msg_size >> 8) & 0xFF,
              msg_size & 0xFF,
          },
  };

  pb_ostream_t stream = {.callback = &_usb_write,
                         .state = &state,
                         .max_size = SIZE_MAX,
                         .bytes_written = 0,
                         .errmsg = NULL};

  if (false == pb_encode(&stream, fields, msg)) {
    return secfalse;
  }

  _usb_write_flush(&state);

  return sectrue;
}

#define MSG_SEND_INIT(TYPE) TYPE msg_send = TYPE##_init_default
#define MSG_SEND_ASSIGN_REQUIRED_VALUE(FIELD, VALUE) \
  { msg_send.FIELD = VALUE; }
#define MSG_SEND_ASSIGN_VALUE(FIELD, VALUE) \
  {                                         \
    msg_send.has_##FIELD = true;            \
    msg_send.FIELD = VALUE;                 \
  }
#define MSG_SEND_ASSIGN_STRING(FIELD, VALUE)                    \
  {                                                             \
    msg_send.has_##FIELD = true;                                \
    memzero(msg_send.FIELD, sizeof(msg_send.FIELD));            \
    strncpy(msg_send.FIELD, VALUE, sizeof(msg_send.FIELD) - 1); \
  }
#define MSG_SEND_ASSIGN_STRING_LEN(FIELD, VALUE, LEN)                     \
  {                                                                       \
    msg_send.has_##FIELD = true;                                          \
    memzero(msg_send.FIELD, sizeof(msg_send.FIELD));                      \
    strncpy(msg_send.FIELD, VALUE, MIN(LEN, sizeof(msg_send.FIELD) - 1)); \
  }
#define MSG_SEND_ASSIGN_BYTES(FIELD, VALUE, LEN)                  \
  {                                                               \
    msg_send.has_##FIELD = true;                                  \
    memzero(msg_send.FIELD.bytes, sizeof(msg_send.FIELD.bytes));  \
    memcpy(msg_send.FIELD.bytes, VALUE,                           \
           MIN(LEN, sizeof(msg_send.FIELD.bytes)));               \
    msg_send.FIELD.size = MIN(LEN, sizeof(msg_send.FIELD.bytes)); \
  }

#define MSG_SEND_ASSIGN_REQUIRED_BYTES(FIELD, VALUE, LEN)         \
  {                                                               \
    memzero(msg_send.FIELD.bytes, sizeof(msg_send.FIELD.bytes));  \
    memcpy(msg_send.FIELD.bytes, VALUE,                           \
           MIN(LEN, sizeof(msg_send.FIELD.bytes)));               \
    msg_send.FIELD.size = MIN(LEN, sizeof(msg_send.FIELD.bytes)); \
  }
#define MSG_SEND(TYPE) \
  _send_msg(iface_num, MessageType_MessageType_##TYPE, TYPE##_fields, &msg_send)

#define STR(X) #X
#define VERSTR(X) STR(X)

typedef struct {
  uint8_t iface_num;
  uint8_t packet_index;
  uint8_t packet_pos;
  uint8_t *buf;
} usb_read_state;

static void _usb_webusb_read_retry(uint8_t iface_num, uint8_t *buf) {
  for (int retry = 0;; retry++) {
    int r =
        usb_webusb_read_blocking(iface_num, buf, USB_PACKET_SIZE, USB_TIMEOUT);
    if (r != USB_PACKET_SIZE) {  // reading failed
      if (r == 0 && retry < 10) {
        // only timeout => let's try again
      } else {
        // error
        error_shutdown("Error reading", "from USB.", "Try different",
                       "USB cable.");
      }
    }
    return;  // success
  }
}

/* we don't use secbool/sectrue/secfalse here as it is a nanopb api */
static bool _usb_read(pb_istream_t *stream, uint8_t *buf, size_t count) {
  usb_read_state *state = (usb_read_state *)(stream->state);

  size_t read = 0;
  // while we have data left
  while (read < count) {
    size_t remaining = count - read;
    // if all remaining data fit into our packet
    if (state->packet_pos + remaining <= USB_PACKET_SIZE) {
      // append data from buf to state->buf
      memcpy(buf + read, state->buf + state->packet_pos, remaining);
      // advance position
      state->packet_pos += remaining;
      // and return
      return true;
    } else {
      // append data that fits
      memcpy(buf + read, state->buf + state->packet_pos,
             USB_PACKET_SIZE - state->packet_pos);
      read += USB_PACKET_SIZE - state->packet_pos;
      if (host_channel == CHANNEL_USB) {
        // read next packet (with retry)
        _usb_webusb_read_retry(state->iface_num, state->buf);
      } else {
        if (spi_slave_poll(state->buf) == 0) {
          spi_read_retry(state->buf);
        }
      }
      // prepare next packet
      state->packet_index++;
      state->packet_pos = MSG_HEADER2_LEN;
    }
  }

  return true;
}

static void _usb_read_flush(usb_read_state *state) { (void)state; }

static secbool _recv_msg(uint8_t iface_num, uint32_t msg_size, uint8_t *buf,
                         const pb_msgdesc_t *fields, void *msg) {
  usb_read_state state = {.iface_num = iface_num,
                          .packet_index = 0,
                          .packet_pos = MSG_HEADER1_LEN,
                          .buf = buf};

  pb_istream_t stream = {.callback = &_usb_read,
                         .state = &state,
                         .bytes_left = msg_size,
                         .errmsg = NULL};

  if (false == pb_decode_noinit(&stream, fields, msg)) {
    return secfalse;
  }

  _usb_read_flush(&state);

  return sectrue;
}

#define MSG_RECV_INIT(TYPE) TYPE msg_recv = TYPE##_init_default
#define MSG_RECV_CALLBACK(FIELD, CALLBACK, ARGUMENT) \
  {                                                  \
    msg_recv.FIELD.funcs.decode = &CALLBACK;         \
    msg_recv.FIELD.arg = (void *)ARGUMENT;           \
  }
#define MSG_RECV(TYPE) \
  _recv_msg(iface_num, msg_size, buf, TYPE##_fields, &msg_recv)

void send_success(uint8_t iface_num, const char *text) {
  MSG_SEND_INIT(Success);
  MSG_SEND_ASSIGN_STRING(message, text);
  MSG_SEND(Success);
}

void send_failure(uint8_t iface_num, FailureType type, const char *text) {
  MSG_SEND_INIT(Failure);
  MSG_SEND_ASSIGN_VALUE(code, type);
  MSG_SEND_ASSIGN_STRING(message, text);
  MSG_SEND(Failure);
}

void send_user_abort(uint8_t iface_num, const char *msg) {
  MSG_SEND_INIT(Failure);
  MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ActionCancelled);
  MSG_SEND_ASSIGN_STRING(message, msg);
  MSG_SEND(Failure);
}

static void send_msg_features(uint8_t iface_num,
                              const vendor_header *const vhdr,
                              const image_header *const hdr) {
  MSG_SEND_INIT(Features);
  if (device_is_factory_mode()) {
    uint32_t cert_len = 0;
    uint32_t init_state = 0;
    MSG_SEND_ASSIGN_STRING(vendor, "onekey.so");
    MSG_SEND_ASSIGN_REQUIRED_VALUE(major_version, VERSION_MAJOR);
    MSG_SEND_ASSIGN_REQUIRED_VALUE(minor_version, VERSION_MINOR);
    MSG_SEND_ASSIGN_REQUIRED_VALUE(patch_version, VERSION_PATCH);
    MSG_SEND_ASSIGN_VALUE(bootloader_mode, true);
    MSG_SEND_ASSIGN_STRING(model, "factory");
    init_state |= device_serial_set() ? 1 : 0;
    init_state |= se_get_certificate_len(&cert_len) ? (1 << 2) : 0;
    MSG_SEND_ASSIGN_VALUE(initstates, init_state);

  } else {
    MSG_SEND_ASSIGN_STRING(vendor, "onekey.so");
    MSG_SEND_ASSIGN_REQUIRED_VALUE(major_version, VERSION_MAJOR);
    MSG_SEND_ASSIGN_REQUIRED_VALUE(minor_version, VERSION_MINOR);
    MSG_SEND_ASSIGN_REQUIRED_VALUE(patch_version, VERSION_PATCH);
    MSG_SEND_ASSIGN_VALUE(bootloader_mode, true);
    MSG_SEND_ASSIGN_STRING(model, "T");
    if (vhdr && hdr) {
      MSG_SEND_ASSIGN_VALUE(firmware_present, true);
      MSG_SEND_ASSIGN_VALUE(fw_major, (hdr->version & 0xFF));
      MSG_SEND_ASSIGN_VALUE(fw_minor, ((hdr->version >> 8) & 0xFF));
      MSG_SEND_ASSIGN_VALUE(fw_patch, ((hdr->version >> 16) & 0xFF));
      MSG_SEND_ASSIGN_STRING_LEN(fw_vendor, vhdr->vstr, vhdr->vstr_len);
      const char *ver_str = format_ver("%d.%d.%d", hdr->onekey_version);
      MSG_SEND_ASSIGN_STRING_LEN(onekey_version, ver_str, strlen(ver_str));
      MSG_SEND_ASSIGN_STRING_LEN(onekey_firmware_version, ver_str,
                                 strlen(ver_str));
    } else {
      MSG_SEND_ASSIGN_VALUE(firmware_present, false);
    }
    if (ble_name_state()) {
      MSG_SEND_ASSIGN_STRING_LEN(ble_name, ble_get_name(), BLE_NAME_LEN);
      MSG_SEND_ASSIGN_STRING_LEN(onekey_ble_name, ble_get_name(), BLE_NAME_LEN);
    }
    if (ble_ver_state()) {
      char *ble_version = ble_get_ver();
      MSG_SEND_ASSIGN_STRING_LEN(ble_ver, ble_version, strlen(ble_version));
      MSG_SEND_ASSIGN_STRING_LEN(onekey_ble_version, ble_version,
                                 strlen(ble_version));
    }
    if (ble_switch_state()) {
      MSG_SEND_ASSIGN_VALUE(ble_enable, ble_get_switch());
    }
    char *se_version = se_get_version();
    if (se_version) {
      MSG_SEND_ASSIGN_STRING_LEN(se_ver, se_version, strlen(se_version));
    }

    char *serial = NULL;
    if (device_get_serial(&serial)) {
      MSG_SEND_ASSIGN_STRING_LEN(serial_no, serial, strlen(serial));
    }
    char *board_version = get_boardloader_version();
    MSG_SEND_ASSIGN_STRING_LEN(boardloader_version, board_version,
                               strlen(board_version));
    MSG_SEND_ASSIGN_STRING_LEN(onekey_board_version, board_version,
                               strlen(board_version));

    char *boot_version = (VERSTR(VERSION_MAJOR) "." VERSTR(
        VERSION_MINOR) "." VERSTR(VERSION_PATCH));
    MSG_SEND_ASSIGN_STRING_LEN(onekey_boot_version, boot_version,
                               strlen(boot_version));

    MSG_SEND_ASSIGN_VALUE(onekey_device_type, OneKeyDeviceType_TOUCH);
    MSG_SEND_ASSIGN_VALUE(onekey_se_type, OneKeySeType_SE608A);
  }

  MSG_SEND(Features);
}

static void send_msg_features_ex(uint8_t iface_num,
                                 const vendor_header *const vhdr,
                                 const image_header *const hdr) {
  MSG_SEND_INIT(OnekeyFeatures);

  if (vhdr && hdr) {
    const char *ver_str = format_ver("%d.%d.%d", hdr->onekey_version);
    MSG_SEND_ASSIGN_STRING_LEN(onekey_firmware_version, ver_str,
                               strlen(ver_str));
    uint8_t *fimware_hash = get_firmware_hash();
    MSG_SEND_ASSIGN_BYTES(onekey_firmware_hash, fimware_hash, 32);
  }
  if (ble_name_state()) {
    MSG_SEND_ASSIGN_STRING_LEN(onekey_ble_name, ble_get_name(), BLE_NAME_LEN);
  }
  if (ble_ver_state()) {
    char *ble_version = ble_get_ver();
    MSG_SEND_ASSIGN_STRING_LEN(onekey_ble_version, ble_version,
                               strlen(ble_version));
  }

  char *serial = NULL;
  if (device_get_serial(&serial)) {
    MSG_SEND_ASSIGN_STRING_LEN(onekey_serial_no, serial, strlen(serial));
  }
  char *board_version = get_boardloader_version();
  MSG_SEND_ASSIGN_STRING_LEN(onekey_board_version, board_version,
                             strlen(board_version));
  uint8_t *board_hash = get_boardloader_hash();
  MSG_SEND_ASSIGN_BYTES(onekey_board_hash, board_hash, 32);

  char *boot_version = (VERSTR(VERSION_MAJOR) "." VERSTR(
      VERSION_MINOR) "." VERSTR(VERSION_PATCH));
  MSG_SEND_ASSIGN_STRING_LEN(onekey_boot_version, boot_version,
                             strlen(boot_version));

  uint8_t *boot_hash = get_bootloader_hash();
  MSG_SEND_ASSIGN_BYTES(onekey_boot_hash, boot_hash, 32);
  MSG_SEND_ASSIGN_STRING_LEN(onekey_boot_build_id, (char *)BUILD_COMMIT,
                             strlen((char *)BUILD_COMMIT));
  MSG_SEND_ASSIGN_VALUE(onekey_device_type, OneKeyDeviceType_TOUCH);
  MSG_SEND_ASSIGN_VALUE(onekey_se_type, OneKeySeType_SE608A);

  MSG_SEND(OnekeyFeatures);
}

void process_msg_Initialize(uint8_t iface_num, uint32_t msg_size, uint8_t *buf,
                            const vendor_header *const vhdr,
                            const image_header *const hdr) {
  MSG_RECV_INIT(Initialize);
  MSG_RECV(Initialize);
  send_msg_features(iface_num, vhdr, hdr);
}

void process_msg_GetFeatures(uint8_t iface_num, uint32_t msg_size, uint8_t *buf,
                             const vendor_header *const vhdr,
                             const image_header *const hdr) {
  MSG_RECV_INIT(GetFeatures);
  MSG_RECV(GetFeatures);
  send_msg_features(iface_num, vhdr, hdr);
}

void process_msg_OnekeyGetFeatures(uint8_t iface_num, uint32_t msg_size,
                                   uint8_t *buf,
                                   const vendor_header *const vhdr,
                                   const image_header *const hdr) {
  MSG_RECV_INIT(OnekeyGetFeatures);
  MSG_RECV(OnekeyGetFeatures);
  send_msg_features_ex(iface_num, vhdr, hdr);
}

void process_msg_Ping(uint8_t iface_num, uint32_t msg_size, uint8_t *buf) {
  MSG_RECV_INIT(Ping);
  MSG_RECV(Ping);

  MSG_SEND_INIT(Success);
  MSG_SEND_ASSIGN_STRING(message, msg_recv.message);
  MSG_SEND(Success);
}

void process_msg_Reboot(uint8_t iface_num, uint32_t msg_size, uint8_t *buf) {
  MSG_RECV_INIT(Reboot);
  MSG_RECV(Reboot);

  switch (msg_recv.reboot_type) {
    case RebootType_Normal: {
      MSG_SEND_INIT(Success);
      MSG_SEND_ASSIGN_STRING(message, "Reboot type Normal accepted!");
      MSG_SEND(Success);
    }
      *STAY_IN_FLAG_ADDR = 0;
      restart();
      break;
    case RebootType_Boardloader: {
      MSG_SEND_INIT(Success);
      MSG_SEND_ASSIGN_STRING(message, "Reboot type Boardloader accepted!");
      MSG_SEND(Success);
    }
      reboot_to_board();
      break;
    case RebootType_BootLoader: {
      MSG_SEND_INIT(Success);
      MSG_SEND_ASSIGN_STRING(message, "Reboot type BootLoader accepted!");
      MSG_SEND(Success);
    }
      reboot_to_boot();
      break;

    default: {
      MSG_SEND_INIT(Failure);
      MSG_SEND_ASSIGN_STRING(message, "Reboot type invalid!");
      MSG_SEND(Failure);
    } break;
  }
}

static uint32_t firmware_remaining, firmware_len, firmware_block,
    chunk_requested;

void process_msg_FirmwareErase(uint8_t iface_num, uint32_t msg_size,
                               uint8_t *buf) {
  firmware_remaining = 0;
  firmware_block = 0;
  chunk_requested = 0;

  MSG_RECV_INIT(FirmwareErase);
  MSG_RECV(FirmwareErase);

  firmware_len = firmware_remaining = msg_recv.has_length ? msg_recv.length : 0;
  if ((firmware_remaining > 0) &&
      ((firmware_remaining % sizeof(uint32_t)) == 0) &&
      (firmware_remaining <= (FIRMWARE_SECTORS_COUNT * IMAGE_CHUNK_SIZE))) {
    // request new firmware
    chunk_requested = (firmware_remaining > IMAGE_INIT_CHUNK_SIZE)
                          ? IMAGE_INIT_CHUNK_SIZE
                          : firmware_remaining;
    MSG_SEND_INIT(FirmwareRequest);
    MSG_SEND_ASSIGN_VALUE(offset, 0);
    MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
    MSG_SEND(FirmwareRequest);
  } else {
    // invalid firmware size
    MSG_SEND_INIT(Failure);
    MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
    MSG_SEND_ASSIGN_STRING(message, "Wrong firmware size");
    MSG_SEND(Failure);
  }
}

static uint32_t chunk_size = 0;

#if defined(STM32H747xx)
// USE SDRAM
uint8_t *const chunk_buffer =
    (uint8_t *const)FMC_SDRAM_BOOLOADER_BUFFER_ADDRESS;
#else
// SRAM is unused, so we can use it for chunk buffer
uint8_t *const chunk_buffer = (uint8_t *const)0x20000000;
#endif
// __attribute__((section(".buf"))) uint32_t chunk_buffer[IMAGE_CHUNK_SIZE / 4];

// #define CHUNK_BUFFER_PTR ((const uint8_t *const)&chunk_buffer)

/* we don't use secbool/sectrue/secfalse here as it is a nanopb api */
static bool _read_payload(pb_istream_t *stream, const pb_field_t *field,
                          void **arg) {
#define BUFSIZE 32768

  uint32_t offset = (uint32_t)(*arg);
  uint32_t buffer_size = BUFSIZE;

  if (update_mode == UPDATE_BLE) {
    buffer_size = 4096;
  }

  if (stream->bytes_left > IMAGE_CHUNK_SIZE) {
    chunk_size = 0;
    return false;
  }

  if (offset == 0) {
    // clear chunk buffer
    memset(chunk_buffer, 0xFF, IMAGE_CHUNK_SIZE);
  }

  uint32_t chunk_written = offset;
  chunk_size = offset + stream->bytes_left;

  while (stream->bytes_left) {
    // update loader but skip first block
    if (update_mode == UPDATE_BLE) {
      ui_screen_install_progress_upload(1000 * chunk_written / firmware_len);
    } else {
      if (firmware_block > 0) {
        ui_screen_install_progress_upload(
            250 + 750 * (firmware_block * IMAGE_CHUNK_SIZE + chunk_written) /
                      (firmware_block * IMAGE_CHUNK_SIZE + firmware_remaining));
      }
    }

    // read data
    if (!pb_read(stream, (pb_byte_t *)(chunk_buffer + chunk_written),
                 (stream->bytes_left > buffer_size) ? buffer_size
                                                    : stream->bytes_left)) {
      chunk_size = 0;
      return false;
    }
    chunk_written += buffer_size;
  }

  if (update_mode == UPDATE_BLE) {
    ui_screen_install_progress_upload(1000 * chunk_written / firmware_len);
  }

  return true;
}

secbool load_vendor_header_keys(const uint8_t *const data,
                                vendor_header *const vhdr);

static int version_compare(uint32_t vera, uint32_t verb) {
  int a, b;
  a = vera & 0xFF;
  b = verb & 0xFF;
  if (a != b) return a - b;
  a = (vera >> 8) & 0xFF;
  b = (verb >> 8) & 0xFF;
  if (a != b) return a - b;
  a = (vera >> 16) & 0xFF;
  b = (verb >> 16) & 0xFF;
  if (a != b) return a - b;
  a = (vera >> 24) & 0xFF;
  b = (verb >> 24) & 0xFF;
  return a - b;
}

static void detect_installation(vendor_header *current_vhdr,
                                image_header *current_hdr,
                                const vendor_header *const new_vhdr,
                                const image_header *const new_hdr,
                                secbool *is_new, secbool *is_upgrade,
                                secbool *is_downgrade_wipe) {
  *is_new = secfalse;
  *is_upgrade = secfalse;
  *is_downgrade_wipe = secfalse;
  if (sectrue !=
      load_vendor_header_keys((const uint8_t *)FIRMWARE_START, current_vhdr)) {
    *is_new = sectrue;
    return;
  }
  if (sectrue !=
      load_image_header((const uint8_t *)FIRMWARE_START + current_vhdr->hdrlen,
                        FIRMWARE_IMAGE_MAGIC, FIRMWARE_IMAGE_MAXSIZE,
                        current_vhdr->vsig_m, current_vhdr->vsig_n,
                        current_vhdr->vpub, current_hdr)) {
    *is_new = sectrue;
    return;
  }
  uint8_t hash1[32], hash2[32];
  vendor_header_hash(new_vhdr, hash1);
  vendor_header_hash(current_vhdr, hash2);
  if (0 != memcmp(hash1, hash2, 32)) {
    return;
  }
  if (version_compare(new_hdr->onekey_version, current_hdr->onekey_version) <
      0) {
    *is_downgrade_wipe = sectrue;
    return;
  }
  *is_upgrade = sectrue;
}

static int firmware_upload_chunk_retry = FIRMWARE_UPLOAD_CHUNK_RETRY_COUNT;
static uint32_t headers_offset = 0;
static uint32_t read_offset = 0;

int process_msg_FirmwareUpload(uint8_t iface_num, uint32_t msg_size,
                               uint8_t *buf) {
  MSG_RECV_INIT(FirmwareUpload);
  MSG_RECV_CALLBACK(payload, _read_payload, read_offset);
  const secbool r = MSG_RECV(FirmwareUpload);

  if (sectrue != r || chunk_size != (chunk_requested + read_offset)) {
    MSG_SEND_INIT(Failure);
    MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
    MSG_SEND_ASSIGN_STRING(message, "Invalid chunk size");
    MSG_SEND(Failure);
    return -1;
  }

  static image_header hdr, ble_hdr;
  static secbool is_upgrade = secfalse;
  static secbool is_downgrade_wipe = secfalse;

  if (firmware_block == 0) {
    if (headers_offset == 0) {
      if (memcmp(chunk_buffer, "5283", 4) == 0) {
        update_mode = UPDATE_BLE;
        if (sectrue !=
            load_ble_image_header(chunk_buffer, FIRMWARE_IMAGE_MAGIC_BLE,
                                  FIRMWARE_IMAGE_MAXSIZE_BLE, &ble_hdr)) {
          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid firmware header");
          MSG_SEND(Failure);
          return -3;
        }
        ui_fadeout();
        ui_install_ble_confirm();
        ui_fadein();

        int response = INPUT_CANCEL;
        response = ui_input_poll(INPUT_CONFIRM | INPUT_CANCEL, true);

        if (INPUT_CANCEL == response) {
          ui_fadeout();
          ui_bootloader_first(NULL);
          ui_fadein();
          send_user_abort(iface_num, "Firmware install cancelled");
          update_mode = 0;
          return -4;
        }

        ui_fadeout();
        ui_screen_install_start();
        ui_fadein();

        headers_offset = IMAGE_HEADER_SIZE;
        read_offset = IMAGE_INIT_CHUNK_SIZE;

        firmware_remaining -= read_offset;

        chunk_requested = (firmware_remaining > IMAGE_CHUNK_SIZE)
                              ? IMAGE_CHUNK_SIZE
                              : firmware_remaining;

        // request the rest of the first chunk
        MSG_SEND_INIT(FirmwareRequest);
        MSG_SEND_ASSIGN_VALUE(offset, read_offset);
        MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
        MSG_SEND(FirmwareRequest);

      } else {
        update_mode = UPDATE_ST;
        // first block and headers are not yet parsed
        vendor_header vhdr;
        if (sectrue != load_vendor_header_keys(chunk_buffer, &vhdr)) {
          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid vendor header");
          MSG_SEND(Failure);
          return -2;
        }
        if (sectrue != load_image_header(chunk_buffer + vhdr.hdrlen,
                                         FIRMWARE_IMAGE_MAGIC,
                                         FIRMWARE_IMAGE_MAXSIZE, vhdr.vsig_m,
                                         vhdr.vsig_n, vhdr.vpub, &hdr)) {
          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid firmware header");
          MSG_SEND(Failure);
          return -3;
        }

        vendor_header current_vhdr;
        image_header current_hdr;
        secbool is_new = secfalse;
        detect_installation(&current_vhdr, &current_hdr, &vhdr, &hdr, &is_new,
                            &is_upgrade, &is_downgrade_wipe);

        int response = INPUT_CANCEL;
        if (sectrue == is_new) {
          // new installation - auto confirm
          response = INPUT_CONFIRM;
        } else if (sectrue == is_upgrade) {
          // firmware upgrade
          ui_fadeout();
#if PRODUCTION_MODEL == 'H'
          ui_install_confirm(&current_hdr, &hdr);
#else
          ui_screen_install_confirm_upgrade(&vhdr, &hdr);
#endif
          ui_fadein();
#if PRODUCTION_MODEL == 'H'
          response = ui_input_poll(INPUT_CONFIRM | INPUT_CANCEL, true);
#else
          response = ui_user_input(INPUT_CONFIRM | INPUT_CANCEL);
#endif
        } else {
          // downgrade with wipe or new firmware vendor
          ui_fadeout();
          ui_screen_install_confirm_newvendor_or_downgrade_wipe(
              &vhdr, &hdr, is_downgrade_wipe);
          ui_fadein();
#if PRODUCTION_MODEL == 'H'
          response = ui_input_poll(INPUT_CONFIRM | INPUT_CANCEL, true);
#else
          response = ui_user_input(INPUT_CONFIRM | INPUT_CANCEL);
#endif
        }

        if (INPUT_CANCEL == response) {
          ui_fadeout();
#if PRODUCTION_MODEL == 'H'
          ui_bootloader_first(&current_hdr);
#else
          ui_screen_firmware_info(&current_vhdr, &current_hdr);
#endif
          ui_fadein();
          send_user_abort(iface_num, "Firmware install cancelled");
          update_mode = 0;
          return -4;
        }

        ui_fadeout();
        ui_screen_install_start();
        ui_fadein();

        headers_offset = IMAGE_HEADER_SIZE + vhdr.hdrlen;
        read_offset = IMAGE_INIT_CHUNK_SIZE;

        // request the rest of the first chunk
        MSG_SEND_INIT(FirmwareRequest);
        chunk_requested = IMAGE_CHUNK_SIZE - read_offset;
        MSG_SEND_ASSIGN_VALUE(offset, read_offset);
        MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
        MSG_SEND(FirmwareRequest);

        firmware_remaining -= read_offset;
      }

      return (int)firmware_remaining;
    } else {
      // first block with the headers parsed -> the first chunk is now complete
      read_offset = 0;

      if (update_mode == UPDATE_BLE) {
      } else {
        // if firmware is not upgrade, erase storage
        if (sectrue != is_upgrade) {
          se_set_wiping(true);
          se_reset_storage();
          ensure(
              flash_erase_sectors(STORAGE_SECTORS, STORAGE_SECTORS_COUNT, NULL),
              NULL);
          se_reset_state();
        }
        ensure(flash_erase_sectors(FIRMWARE_SECTORS, FIRMWARE_SECTORS_COUNT,
                                   ui_screen_install_progress_erase),
               NULL);
      }
    }
  }
  static BLAKE2S_CTX ctx;
  static bool packet_flag = false;

  if (update_mode == UPDATE_BLE) {
    uint8_t *p_init = (uint8_t *)chunk_buffer + headers_offset;
    uint32_t init_data_len = p_init[0] + (p_init[1] << 8);
    bool update_status = false;

    MSG_SEND_INIT(Success);
    MSG_SEND_ASSIGN_STRING(message, "Bluetooth download success");
    MSG_SEND(Success);

    hal_delay(200);

    update_status = updateBle(p_init + 4, init_data_len,
                              chunk_buffer + headers_offset + BLE_INIT_DATA_LEN,
                              ble_hdr.codelen - BLE_INIT_DATA_LEN);

    if (update_status == false) {
      return -6;
    } else {
      return 0;
    }

  } else {
    // should not happen, but double-check
    if (firmware_block >= FIRMWARE_SECTORS_COUNT) {
      MSG_SEND_INIT(Failure);
      MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
      MSG_SEND_ASSIGN_STRING(message, "Firmware too big");
      MSG_SEND(Failure);
      return -5;
    }

    if ((firmware_remaining - chunk_requested) == 0) {
      if (packet_flag) {
        uint8_t hash[BLAKE2S_DIGEST_LENGTH];
        blake2s_Update(&ctx, chunk_buffer + headers_offset,
                       chunk_size - headers_offset);
        blake2s_Final(&ctx, hash, BLAKE2S_DIGEST_LENGTH);
        if (memcmp(hdr.hashes + (firmware_block / 2) * 32, hash,
                   BLAKE2S_DIGEST_LENGTH) != 0) {
          if (firmware_upload_chunk_retry > 0) {
            --firmware_upload_chunk_retry;
            MSG_SEND_INIT(FirmwareRequest);
            MSG_SEND_ASSIGN_VALUE(offset, firmware_block * IMAGE_CHUNK_SIZE);
            MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
            MSG_SEND(FirmwareRequest);
            return (int)firmware_remaining;
          }

          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid chunk hash");
          MSG_SEND(Failure);
          return -6;
        }
        packet_flag = false;
      } else {
        if (sectrue != check_single_hash(hdr.hashes + (firmware_block / 2) * 32,
                                         chunk_buffer + headers_offset,
                                         chunk_size - headers_offset)) {
          if (firmware_upload_chunk_retry > 0) {
            --firmware_upload_chunk_retry;
            MSG_SEND_INIT(FirmwareRequest);
            MSG_SEND_ASSIGN_VALUE(offset, firmware_block * IMAGE_CHUNK_SIZE);
            MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
            MSG_SEND(FirmwareRequest);
            return (int)firmware_remaining;
          }

          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid chunk hash");
          MSG_SEND(Failure);
          return -6;
        }
      }
    } else {
      if ((firmware_block % 2) == 0) {
        packet_flag = true;
        blake2s_Init(&ctx, BLAKE2S_DIGEST_LENGTH);
        blake2s_Update(&ctx, chunk_buffer + headers_offset,
                       chunk_size - headers_offset);

      } else {
        packet_flag = false;
        uint8_t hash[BLAKE2S_DIGEST_LENGTH];
        blake2s_Update(&ctx, chunk_buffer + headers_offset,
                       chunk_size - headers_offset);
        blake2s_Final(&ctx, hash, BLAKE2S_DIGEST_LENGTH);
        if (memcmp(hdr.hashes + (firmware_block / 2) * 32, hash,
                   BLAKE2S_DIGEST_LENGTH) != 0) {
          if (firmware_upload_chunk_retry > 0) {
            --firmware_upload_chunk_retry;
            MSG_SEND_INIT(FirmwareRequest);
            MSG_SEND_ASSIGN_VALUE(offset, firmware_block * IMAGE_CHUNK_SIZE);
            MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
            MSG_SEND(FirmwareRequest);
            return (int)firmware_remaining;
          }

          MSG_SEND_INIT(Failure);
          MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
          MSG_SEND_ASSIGN_STRING(message, "Invalid chunk hash");
          MSG_SEND(Failure);
          return -6;
        }
      }
    }

    ensure(flash_unlock_write(), NULL);

#if defined(STM32H747xx)
    const uint32_t *const src = (const uint32_t *const)chunk_buffer;
    for (int i = 0; i < chunk_size / (sizeof(uint32_t) * 8); i++) {
      ensure(flash_write_words(FIRMWARE_SECTORS[firmware_block],
                               i * (sizeof(uint32_t) * 8),
                               (uint32_t *)&src[8 * i]),
             NULL);
    }

#else
    const uint32_t *const src = (const uint32_t *const)chunk_buffer;
    for (int i = 0; i < chunk_size / sizeof(uint32_t); i++) {
      ensure(flash_write_word(FIRMWARE_SECTORS[firmware_block],
                              i * sizeof(uint32_t), src[i]),
             NULL);
    }
#endif
    ensure(flash_lock_write(), NULL);
  }

  headers_offset = 0;
  firmware_remaining -= chunk_requested;
  firmware_block++;
  firmware_upload_chunk_retry = FIRMWARE_UPLOAD_CHUNK_RETRY_COUNT;

  if (firmware_remaining > 0) {
    chunk_requested = (firmware_remaining > IMAGE_CHUNK_SIZE)
                          ? IMAGE_CHUNK_SIZE
                          : firmware_remaining;
    MSG_SEND_INIT(FirmwareRequest);
    MSG_SEND_ASSIGN_VALUE(offset, firmware_block * IMAGE_CHUNK_SIZE);
    MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
    MSG_SEND(FirmwareRequest);
  } else {
    MSG_SEND_INIT(Success);
    MSG_SEND(Success);
  }
  return (int)firmware_remaining;
}

int process_msg_WipeDevice(uint8_t iface_num, uint32_t msg_size, uint8_t *buf) {
#if PRODUCTION_MODEL == 'H'
  static const uint8_t sectors[] = {
      FLASH_SECTOR_STORAGE_1,
      FLASH_SECTOR_STORAGE_2,
      FLASH_SECTOR_FIRMWARE_START,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      FLASH_SECTOR_FIRMWARE_END,
      FLASH_SECTOR_FIRMWARE_EXTRA_START,
      17,
      18,
      19,
      20,
      21,
      22,
      23,
      24,
      25,
      26,
      27,
      28,
      29,
      30,
      FLASH_SECTOR_FIRMWARE_EXTRA_END,
  };
#else
  static const uint8_t sectors[] = {
      FLASH_SECTOR_STORAGE_1,
      FLASH_SECTOR_STORAGE_2,
      // 3,  // skip because of MPU protection
      FLASH_SECTOR_FIRMWARE_START,
      7,
      8,
      9,
      10,
      FLASH_SECTOR_FIRMWARE_END,
      FLASH_SECTOR_UNUSED_START,
      13,
      14,
      // FLASH_SECTOR_UNUSED_END,  // skip because of MPU protection
      FLASH_SECTOR_FIRMWARE_EXTRA_START,
      18,
      19,
      20,
      21,
      22,
      FLASH_SECTOR_FIRMWARE_EXTRA_END,
  };
#endif
#if PRODUCTION_MODEL == 'H'
  se_set_wiping(true);
  se_reset_storage();
  se_reset_state();
#endif
  if (sectrue !=
      flash_erase_sectors(sectors, sizeof(sectors), ui_screen_wipe_progress)) {
    MSG_SEND_INIT(Failure);
    MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
    MSG_SEND_ASSIGN_STRING(message, "Could not erase flash");
    MSG_SEND(Failure);
    return -1;
  } else {
    MSG_SEND_INIT(Success);
    MSG_SEND(Success);
    return 0;
  }
}

void process_msg_unknown(uint8_t iface_num, uint32_t msg_size, uint8_t *buf) {
  // consume remaining message
  int remaining_chunks = 0;

  if (msg_size > (USB_PACKET_SIZE - MSG_HEADER1_LEN)) {
    // calculate how many blocks need to be read to drain the message (rounded
    // up to not leave any behind)
    remaining_chunks = (msg_size - (USB_PACKET_SIZE - MSG_HEADER1_LEN) +
                        ((USB_PACKET_SIZE - MSG_HEADER2_LEN) - 1)) /
                       (USB_PACKET_SIZE - MSG_HEADER2_LEN);
  }

  for (int i = 0; i < remaining_chunks; i++) {
    // read next packet (with retry)
    _usb_webusb_read_retry(iface_num, buf);
  }

  MSG_SEND_INIT(Failure);
  MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_UnexpectedMessage);
  MSG_SEND_ASSIGN_STRING(message, "Unexpected message");
  MSG_SEND(Failure);
}

void process_msg_DeviceInfoSettings(uint8_t iface_num, uint32_t msg_size,
                                    uint8_t *buf) {
  MSG_RECV_INIT(DeviceInfoSettings);
  MSG_RECV(DeviceInfoSettings);

  if (msg_recv.has_serial_no) {
    if (!device_set_serial((char *)msg_recv.serial_no)) {
      send_failure(iface_num, FailureType_Failure_ProcessError,
                   "Set serial failed");
    } else {
      send_success(iface_num, "Set applied");
    }
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError, "serial null");
  }
}

void process_msg_GetDeviceInfo(uint8_t iface_num, uint32_t msg_size,
                               uint8_t *buf) {
  MSG_RECV_INIT(GetDeviceInfo);
  MSG_RECV(GetDeviceInfo);

  MSG_SEND_INIT(DeviceInfo);

  char *serial;
  if (device_get_serial(&serial)) {
    MSG_SEND_ASSIGN_STRING(serial_no, serial);
  }
  MSG_SEND(DeviceInfo);
}

void process_msg_ReadSEPublicKey(uint8_t iface_num, uint32_t msg_size,
                                 uint8_t *buf) {
  uint8_t pubkey[64] = {0};
  MSG_RECV_INIT(ReadSEPublicKey);
  MSG_RECV(ReadSEPublicKey);

  MSG_SEND_INIT(SEPublicKey);
  if (se_get_pubkey(pubkey)) {
    MSG_SEND_ASSIGN_REQUIRED_BYTES(public_key, pubkey, 64);
    MSG_SEND(SEPublicKey);
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError,
                 "Get SE pubkey Failed");
  }
}

void process_msg_WriteSEPublicCert(uint8_t iface_num, uint32_t msg_size,
                                   uint8_t *buf) {
  MSG_RECV_INIT(WriteSEPublicCert);
  MSG_RECV(WriteSEPublicCert);

  if (se_write_certificate(msg_recv.public_cert.bytes,
                           msg_recv.public_cert.size)) {
    send_success(iface_num, "Write certificate success");
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError,
                 "Write certificate Failed");
  }
}

void process_msg_ReadSEPublicCert(uint8_t iface_num, uint32_t msg_size,
                                  uint8_t *buf) {
  MSG_RECV_INIT(ReadSEPublicCert);
  MSG_RECV(ReadSEPublicCert);

  uint32_t cert_len = 0;
  uint8_t cert[416] = {0};

  MSG_SEND_INIT(SEPublicCert);
  if (se_read_certificate(cert, &cert_len)) {
    MSG_SEND_ASSIGN_REQUIRED_BYTES(public_cert, cert, cert_len);
    MSG_SEND(SEPublicCert);
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError,
                 "Get certificate failed");
  }
}

void process_msg_SESignMessage(uint8_t iface_num, uint32_t msg_size,
                               uint8_t *buf) {
  MSG_RECV_INIT(SESignMessage);
  MSG_RECV(SESignMessage);

  uint8_t sign[64] = {0};

  MSG_SEND_INIT(SEMessageSignature);

  if (se_sign_message((uint8_t *)msg_recv.message.bytes, msg_recv.message.size,
                      sign)) {
    MSG_SEND_ASSIGN_REQUIRED_BYTES(signature, sign, 64);
    MSG_SEND(SEMessageSignature);
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError, "SE sign failed");
  }
}

void process_msg_FirmwareEraseBLE(uint8_t iface_num, uint32_t msg_size,
                                  uint8_t *buf) {
  firmware_remaining = 0;
  firmware_block = 0;
  chunk_requested = 0;

  MSG_RECV_INIT(FirmwareErase_ex);
  MSG_RECV(FirmwareErase_ex);

  firmware_remaining = msg_recv.has_length ? msg_recv.length : 0;
  if ((firmware_remaining > 0) &&
      (firmware_remaining <= FIRMWARE_IMAGE_MAXSIZE_BLE)) {
    // request new firmware
    chunk_requested = (firmware_remaining > IMAGE_INIT_CHUNK_SIZE)
                          ? IMAGE_INIT_CHUNK_SIZE
                          : firmware_remaining;
    MSG_SEND_INIT(FirmwareRequest);
    MSG_SEND_ASSIGN_VALUE(offset, 0);
    MSG_SEND_ASSIGN_VALUE(length, chunk_requested);
    MSG_SEND(FirmwareRequest);
  } else {
    // invalid firmware size
    MSG_SEND_INIT(Failure);
    MSG_SEND_ASSIGN_VALUE(code, FailureType_Failure_ProcessError);
    MSG_SEND_ASSIGN_STRING(message, "Wrong firmware size");
    MSG_SEND(Failure);
  }
}
