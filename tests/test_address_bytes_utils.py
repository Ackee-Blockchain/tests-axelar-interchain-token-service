from woke.testing import *
from woke.testing.fuzzing import *
from pytypes.tests.AddressBytesUtilsMock import AddressBytesUtilsMock


class AddressBytesUtilsFuzzTest(FuzzTest):
    _mock: AddressBytesUtilsMock

    def pre_sequence(self) -> None:
        self._mock = AddressBytesUtilsMock.deploy()

    @flow()
    def flow_to_address(self) -> None:
        b = random_bytes(20)
        assert self._mock.toAddress(b) == Address(b.hex())

    @flow()
    def flow_to_bytes(self, a: Address) -> None:
        assert self._mock.toBytes(a) == bytes(a)


@default_chain.connect()
def test_address_bytes_utils_fuzz():
    default_chain.set_default_accounts(default_chain.accounts[0])
    AddressBytesUtilsFuzzTest().run(10, 1000)


@default_chain.connect()
def test_address_bytes_utils():
    default_chain.set_default_accounts(default_chain.accounts[0])
    mock = AddressBytesUtilsMock.deploy()

    assert mock.toAddress(b'\x00' * 20) == Address.ZERO
    assert mock.toBytes(Address.ZERO) == b'\x00' * 20

    with must_revert():
        mock.toAddress(b'')
    with must_revert():
        mock.toAddress(b'' * 21)
