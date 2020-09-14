# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TxOut(p.MessageType):
    MESSAGE_WIRE_TYPE = 858

    def __init__(
        self,
        value_sat: int = None,
        pk_script: bytes = None,
    ) -> None:
        self.value_sat = value_sat
        self.pk_script = pk_script

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('value_sat', p.UVarintType, 0),
            2: ('pk_script', p.BytesType, 0),
        }