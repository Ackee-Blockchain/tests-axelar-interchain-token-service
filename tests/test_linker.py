import logging
import random
from typing import Dict

from woke.testing import *
from woke.testing.fuzzing import *

from pytypes.source.contracts.linkerRouter.LinkerRouter import LinkerRouter
from pytypes.source.contracts.proxies.LinkerRouterProxy import LinkerRouterProxy


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class LinkerFuzzTest(FuzzTest):
    _canonical_address: Address
    _linker: LinkerRouter
    _trusted_addresses: Dict[str, Address]

    def pre_sequence(self) -> None:
        self._canonical_address = random_address()
        self._trusted_addresses = {}

        impl = LinkerRouter.deploy(self._canonical_address, [], [])
        assert int.from_bytes(impl.contractId()) == int.from_bytes(keccak256(b'remote-address-validator')) - 1
        proxy = LinkerRouterProxy.deploy(impl, default_chain.accounts[0])
        # constant taken from LinkerRouterProxy.contractId()
        assert int.from_bytes(keccak256(b'remote-address-validator')) - 1 == 0x5d9f4d5e6bb737c289f92f2a319c66ba484357595194acb7c2122e48550eda7c
        self._linker = LinkerRouter(proxy)

    @flow()
    def flow_add_trusted_address(self, addr: Address) -> None:
        chain_name = random_string(1, 10)
        self._linker.addTrustedAddress(chain_name, str(addr))
        self._trusted_addresses[chain_name] = addr

        logger.info(f"Added trusted address {addr} for chain {chain_name}")

    @flow()
    def flow_update_trusted_address(self, addr: Address) -> None:
        if len(self._trusted_addresses) == 0:
            return
        chain_name = random.choice(list(self._trusted_addresses.keys()))
        self._linker.addTrustedAddress(chain_name, str(addr))
        self._trusted_addresses[chain_name] = addr

        logger.info(f"Updated trusted address {addr} for chain {chain_name}")

    @flow()
    def flow_remove_trusted_address(self) -> None:
        if len(self._trusted_addresses) == 0:
            return
        chain_name = random.choice(list(self._trusted_addresses.keys()))
        self._linker.removeTrustedAddress(chain_name)
        del self._trusted_addresses[chain_name]

        logger.info(f"Removed trusted address for chain {chain_name}")

    @flow()
    def flow_test_incorrect(self) -> None:
        if len(self._trusted_addresses) == 0:
            return
        chain_name = random.choice(list(self._trusted_addresses.keys()))
        correct_address = str(self._trusted_addresses[chain_name])
        pos = random_int(0, 39)
        chr = correct_address.lower()[pos + 2]
        new_chr = random.choice([c for c in "0123456789abcdef" if c != chr])
        incorrect_address = correct_address[:pos + 2] + new_chr + correct_address[pos + 3:]

        assert not self._linker.validateSender(chain_name, incorrect_address.lower())
        assert not self._linker.validateSender(chain_name, "0x" + incorrect_address[2:].upper())

        logger.info(f"Tested incorrect address {incorrect_address} for chain {chain_name}")

    @invariant(period=50)
    def invariant_trusted_addresses(self) -> None:
        for chain_name, addr in self._trusted_addresses.items():
            assert self._linker.remoteAddresses(chain_name) == str(addr)
            assert self._linker.validateSender(chain_name, str(addr).lower())
            assert self._linker.validateSender(chain_name, "0x" + str(addr)[2:].upper())
        for _ in range(100):
            chain_name = random_string(1, 10, predicate=lambda s: s not in self._trusted_addresses)
            assert self._linker.remoteAddresses(chain_name) == ""
            assert self._linker.validateSender(chain_name, str(self._canonical_address))


@default_chain.connect()
def test_linker_fuzz():
    a = default_chain.accounts[0]
    default_chain.set_default_accounts(a)

    LinkerFuzzTest().run(10, 1_000)
