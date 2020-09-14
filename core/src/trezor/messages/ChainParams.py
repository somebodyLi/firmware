# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class ChainParams(p.MessageType):
    MESSAGE_WIRE_TYPE = 845

    def __init__(
        self,
        network_name: str = None,
    ) -> None:
        self.network_name = network_name

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('network_name', p.UnicodeType, 0),
        }