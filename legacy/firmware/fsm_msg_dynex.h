/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "monero/monero.h"

void fsm_msgDnxGetAddress(const DnxGetAddress* msg) {
  CHECK_INITIALIZED

  CHECK_PIN

  RESP_INIT(DnxAddress);

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  dnx_get_address(resp->address, node->private_key, false);
  resp->has_address = true;
  if (msg->has_show_display && msg->show_display) {
    char desc[12] = {0};
    strcat(desc, "Dnx");
    strcat(desc, _("Address:"));
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, true, NULL, 0, 0, NULL)) {
      return;
    }
  }

  msg_write(MessageType_MessageType_DnxAddress, resp);
  layoutHome();
}
void fsm_msgDnxUploadTxInfo(const DnxUploadTxInfo* msg) {
  CHECK_INITIALIZED

  CHECK_PIN
  CHECK_PARAM(msg->has_payment_id && msg->payment_id.size == 32,
              "Invalid payment id");
  CHECK_PARAM(msg->inputs_count >= 1 && msg->inputs_count <= 20,
              "Invalid number of inputs");
  CHECK_PARAM(
      msg->address_n_count == 5 && msg->address_n[1] == (29538 | 0x80000000),
      "Invalid address path");
  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  dnx_singing_init(msg);
  if(!layoutDnxTxInfo(msg, node)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action cancelled");
    dnx_singing_abort();
    return;
  }
  RESP_INIT(DnxInputRequest);
  resp->has_request_index = true;
  resp->request_index = ++dnx_input_index;
  resp->has_tx_key = true;
  resp->tx_key.has_ephemeral_tx_sec_key = true;
  resp->tx_key.has_ephemeral_tx_pub_key = true;
  bignum256modm scalar = {0};
  xmr_random_scalar(scalar);
  uint8_t key_seed[32] = {0};
  encodeint(key_seed, scalar);
  ge25519 tx_pub_key = {0};
  ge25519_set_neutral(&tx_pub_key);
  generate_keys(key_seed, &tx_pub_key, tx_sec_key);
  resp->tx_key.ephemeral_tx_sec_key.size = 32;
  resp->tx_key.ephemeral_tx_pub_key.size = 32;
  encodeint(resp->tx_key.ephemeral_tx_sec_key.bytes, tx_sec_key);
  encodepoint(resp->tx_key.ephemeral_tx_pub_key.bytes, &tx_pub_key);
  msg_write(MessageType_MessageType_DnxInputRequest, resp);
}
void fsm_msgDnxInputAck(const DnxInputAck* msg) {
  if (!dnx_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Dynex signing mode");
    layoutHome();
    return;
  };
  if (dnx_input_index <= dnx_inputs_count) {
    ++dnx_input_index;
    RESP_INIT(DnxInputRequest);
    resp->has_computed_key_image = true;
    if (dnx_input_index > dnx_inputs_count) {
      resp->has_request_index = false;
      key_image_synced = true;
    } else {
      resp->has_request_index = true;
      resp->request_index = dnx_input_index;
    }
    ge25519 tx_pub_key = {0};
    ge25519_set_neutral(&tx_pub_key);
    decodepoint(&tx_pub_key, msg->tx_pubkey.bytes);
    resp->computed_key_image.key_image.size = 32;
    resp->computed_key_image.ephemeral_sec_key.size = 32;
    // resp->computed_key_image.ephemeral_pub_key.size = 32;
    dnx_generate_key_image(&tx_pub_key, &spend_pub_key, spend_sec_key,
                           msg->pre_index, view_sec_key,
                           resp->computed_key_image.key_image.bytes,
                           resp->computed_key_image.ephemeral_sec_key.bytes);
    total_input_amounts += msg->amount;
    msg_write(MessageType_MessageType_DnxInputRequest, resp);
  } else {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Dnx image key already synced");
    dnx_singing_abort();
    return;
  }
}
void fsm_msgDnxGetOutputKey(const DnxGetOutputKey* msg) {
  if (!dnx_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Dynex signing mode");
    layoutHome();
    return;
  };
  if (!key_image_synced) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Dnx key image not synced");
    dnx_singing_abort();
    return;
  }
  if (total_input_amounts < amounts + fee) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "insufficient funds");
    dnx_singing_abort();
    return;
  }
  RESP_INIT(DnxOutputKey);
  resp->ephemeral_output_key_count =
      (msg->has_has_change && msg->has_change) ? 2 : 1;
  uint8_t data[64] = {0};
  dnx_base58_addr_decode_check(destination, sizeof(destination) - 1, data,
                               sizeof(data));
  ge25519 destination_view_pub_key = {0};
  ge25519_set_neutral(&destination_view_pub_key);
  ge25519 destination_spend_pub_key = {0};
  ge25519_set_neutral(&destination_spend_pub_key);
  decodepoint(&destination_spend_pub_key, data);
  decodepoint(&destination_view_pub_key, data + 32);
  resp->ephemeral_output_key_count = 1;
  resp->ephemeral_output_key[0].size = 32;
  dnx_generate_output_key(resp->ephemeral_output_key[0].bytes, 0, tx_sec_key,
                          &destination_view_pub_key,
                          &destination_spend_pub_key);
  if (msg->has_has_change && msg->has_change) {
    resp->ephemeral_output_key_count = 2;
    resp->ephemeral_output_key[1].size = 32;
    dnx_generate_output_key(resp->ephemeral_output_key[1].bytes, 1, tx_sec_key,
                            &view_pub_key, &spend_pub_key);
  }
  msg_write(MessageType_MessageType_DnxOutputKey, resp);
  dnx_singing_abort();
  return;
}
