# This file is part of the OneKey project, https://onekey.so/
#
# Copyright (C) 2021 OneKey Team <core@onekey.so>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.


from typing import TYPE_CHECKING, Dict

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address
    from .protobuf import MessageType


@expect(messages.DnxAddress, field="address", ret_type=str)
def get_address(
    client: "TrezorClient", address_n: "Address", show_display: bool = False
) -> "MessageType":
    return client.call(
        messages.DnxGetAddress(address_n=address_n, show_display=show_display)
    )


def sync_tx(client: "TrezorClient", address_n: "Address") -> None:
    res = client.call(
        messages.DnxUploadTxInfo(
            address_n=address_n,
            inputs_count=2,
            to_address="XwmyX7jT9piajavVtQ3mZMFbS7Ps8CmkFdcc8DPHfvbh27pDVLS1mDwG8YbATnNTF36oH92piBB4EetJeytY8dUM2G2axuPax",
            amount=100000000,
            fee=1000000,
            payment_id=b"\x00" * 32)
    )
    """
  TransactionOutputInformation output;
  output.amount = 1401000000;
  output.globalOutputIndex = 9;
  output.outputInTransaction = 1;
  std::memcpy(output.transactionHash.data, HexToBytes("06d748d59f9783d96a12459146ef57e6f5c46461c993af55f89c9225580dfc4f").data(), 32);
  std::memcpy(output.transactionPublicKey.data, HexToBytes("0a8a4c9cd57867aaf3ea35224f45da424b44d1dea288e8db8aa4a937dd2258eb").data(), 32);
  std::memcpy(output.outputKey.data, HexToBytes("8591b7070a50f6dffebfc038d0b672ccea539337e62b2658dd99c8880ce5fcf9").data(), 32);
  outputs.push_back(output);
  TransactionOutputInformation output2;
  output2.amount = 989990000;
  output2.globalOutputIndex = 0;
  output2.outputInTransaction = 1;
  std::memcpy(output2.transactionHash.data, HexToBytes("81edfe5536d01bb8cca5c58dad8abe00adbe6f3121ad70148418b6042fbf60d8").data(), 32);
  std::memcpy(output2.transactionPublicKey.data, HexToBytes("9dc10499d2475c98fb592d133de6a3d3beab490129cd5e57bebb0e2d00dffd2e").data(), 32);
  std::memcpy(output2.outputKey.data, HexToBytes("9f50b4acbd5c4c3b5394a0b71e1ee384c5320c8853293da6132e46ef55f960c1").data(), 32);
  outputs.push_back(output2);
    """
    inputs = [
        {
            "prev_index": 1,
            "tx_pub_key": bytes.fromhex("0a8a4c9cd57867aaf3ea35224f45da424b44d1dea288e8db8aa4a937dd2258eb"),
            "amount": 1401000000,
        },
        {
            "prev_index": 1,
            "tx_pub_key": bytes.fromhex("9dc10499d2475c98fb592d133de6a3d3beab490129cd5e57bebb0e2d00dffd2e"),
            "amount": 989990000,
        }
    ]
    while True:
        if isinstance(res, messages.DnxInputRequest):
            if res.tx_key:
                print("tx_sec_key", res.tx_key.ephemeral_tx_sec_key.hex())
                print("tx_pub_key", res.tx_key.ephemeral_tx_pub_key.hex())
            if res.computed_key_image:
                print("key_image", res.computed_key_image.key_image.hex())
                # print("in_ephemeral_pub_key", res.computed_key_image.ephemeral_pub_key.hex())
                print("in_ephemeral_sec_key", res.computed_key_image.ephemeral_sec_key.hex())
            if res.request_index:
                req_index = res.request_index - 1
                cur_input = inputs[req_index]
                res = client.call(messages.DnxInputAck(
                    pre_index=cur_input["prev_index"],
                    tx_pubkey=cur_input["tx_pub_key"],
                    amount=cur_input["amount"],
                ))
                continue
            break
    res = client.call(messages.DnxGetOutputKey(has_change=True))
    assert isinstance(res, messages.DnxOutputKey)
    for key in res.ephemeral_output_key:
        print("ephemeral_ot_key", key.hex())
