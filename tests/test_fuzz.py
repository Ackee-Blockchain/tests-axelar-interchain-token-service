import logging
import random
import string
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, DefaultDict, Dict, Tuple, Union

from wake.testing import *
from wake.testing.fuzzing import *
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.interfaces.IAxelarExecutable import IAxelarExecutable
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.utils.SafeTransfer import TokenTransferFailed
from pytypes.source.contracts.interchainToken.InterchainToken import InterchainToken
from pytypes.source.contracts.interchainTokenService.InterchainTokenService import InterchainTokenService
from pytypes.source.contracts.interfaces.IERC20BurnableMintable import IERC20BurnableMintable
from pytypes.source.contracts.interfaces.ITokenManager import ITokenManager
from pytypes.source.contracts.interfaces.ITokenManagerProxy import ITokenManagerProxy
from pytypes.source.contracts.interfaces.ITokenManagerType import ITokenManagerType
from pytypes.source.contracts.test.InterchainTokenTest import InterchainTokenTest
from pytypes.source.contracts.tokenManager.implementations.TokenManagerLiquidityPool import TokenManagerLiquidityPool
from pytypes.source.contracts.utils.MockAxelarGateway import MockAxelarGateway
from pytypes.tests.PayloadReceiver import PayloadReceiver
from pytypes.tests.TokenManagerCanonicalMock import TokenManagerCanonicalMock

from .utils import deploy_interchain_token_service


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
chain1 = Chain()
chain2 = Chain()


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint256
    nonce: uint256
    deadline: uint256


class InterchainTokenFuzzTest(FuzzTest):
    _command_counter: int  # used to generate unique command ids for gateways
    _services: Dict[Chain, InterchainTokenService]
    _gateways: Dict[Chain, MockAxelarGateway]
    _payload_receivers: Dict[Chain, PayloadReceiver]
    _balances: Dict[InterchainToken, DefaultDict[Account, int]]
    _allowances: Dict[InterchainToken, DefaultDict[Account, DefaultDict[Account, int]]]
    _last_relay_tx: Optional[TransactionAbc]
    _flow_out_amounts: DefaultDict[ITokenManager, DefaultDict[int, int]]
    _flow_in_amounts: DefaultDict[ITokenManager, DefaultDict[int, int]]

    def _execute_with_flow_limit(
        self,
        callable: Callable[[], TransactionAbc],
        chain: Chain,
        token_id: bytes32,
        amount_in: int,
        amount_out: int,
    ) -> TransactionAbc:
        try:
            return callable()
        except ITokenManager.FlowLimitExceeded as e:
            # enter new epoch and try again
            assert e.tx is not None
            token_manager = ITokenManager(
                self._services[chain].getTokenManagerAddress(token_id),
                chain=chain,
            )
            flow_in = self._flow_in_amounts[token_manager][e.tx.block.timestamp // (6 * 60 * 60)]
            flow_out = self._flow_out_amounts[token_manager][e.tx.block.timestamp // (6 * 60 * 60)]
            assert abs(flow_in + amount_in - flow_out - amount_out) > token_manager.getFlowLimit()
            assert token_manager.getFlowInAmount(block=e.tx.block.number) == flow_in
            assert token_manager.getFlowOutAmount(block=e.tx.block.number) == flow_out
            chain.mine(lambda x: x + 6 * 60 * 60)
            return callable()

    def _express_receive(
        self,
        event: Union[InterchainTokenService.TokenSent, InterchainTokenService.TokenSentWithData],
        destination_chain: Chain,
    ) -> None:
        token_id = event.tokenId
        amount = event.amount
        destination_token_manager = ITokenManager(
            self._services[destination_chain].getTokenManagerAddress(token_id),
            chain=destination_chain,
        )
        destination_token = InterchainToken(
            destination_token_manager.tokenAddress(),
            chain=destination_chain,
        )
        destination_address = Address(event.destinationAddress.hex())
        try:
            express_caller = random.choice([
                a for a in destination_token.chain.accounts
                if self._balances[destination_token][a] >= amount
            ])
        except IndexError:
            # no suitable express caller, mint some tokens
            express_caller = random_account(chain=destination_token.chain)
            IERC20BurnableMintable(destination_token).mint(express_caller, amount)
            self._balances[destination_token][express_caller] += amount

        source_chain = chain1 if destination_chain == chain2 else chain2
        send_hash = keccak256(Abi.encode(
            ["bytes32", "uint256", "uint256"],
            [token_id, source_chain.blocks["latest"].number, amount]
        ))
        assert send_hash == event.sendHash
        destination_token.approve(self._services[destination_chain], amount, from_=express_caller)

        if isinstance(event, InterchainTokenService.TokenSentWithData):
            callable = lambda: self._services[destination_chain].expressReceiveTokenWithData(
                token_id, "chain1" if destination_chain == chain2 else "chain2",
                bytes(event.sourceAddress), destination_address, amount, event.data, send_hash,
                from_=express_caller,
            )
        else:
            callable = lambda: self._services[destination_chain].expressReceiveToken(
                token_id, destination_address, amount, send_hash,
                from_=express_caller,
            )
        self._execute_with_flow_limit(callable, destination_chain, token_id, amount, 0)

    def _relay(self, tx: TransactionAbc) -> None:
        for index, event in enumerate(tx.raw_events):
            if len(event.topics) == 0:
                continue

            if event.topics[0] == MockAxelarGateway.ContractCall.selector:
                sender = Abi.decode(["address"], event.topics[1])[0]
                destination_chain_name, destination_address_str, payload = Abi.decode(
                    ["string", "string", "bytes"], event.data
                )
                destination_chain = chain2 if destination_chain_name == "chain2" else chain1
                destination_gw = self._gateways[destination_chain]
                source_chain_name = "chain1" if destination_chain_name == "chain2" else "chain2"
                command_id = self._command_counter.to_bytes(32, "big")

                try:
                    token_event_raw = next(
                        ev for ev in tx.raw_events
                        if len(ev.topics) > 0 and ev.topics[0] in {
                            InterchainTokenService.TokenSent.selector,
                            InterchainTokenService.TokenSentWithData.selector,
                        }
                    )
                    if token_event_raw.topics[0] == InterchainTokenService.TokenSent.selector:
                        dtoken_id, ddestination_chain, ddestination_address, dsend_hash = Abi.decode(
                            ["bytes32", "string", "bytes", "bytes32"], token_event_raw.data
                        )
                        token_event = InterchainTokenService.TokenSent(
                            dtoken_id,
                            ddestination_chain,
                            ddestination_address,
                            Abi.decode(["uint256"], token_event_raw.topics[1])[0],
                            dsend_hash,
                        )
                    else:
                        dtoken_id, ddestination_chain, ddestination_address, ddata, dsend_hash = Abi.decode(
                            ["bytes32", "string", "bytes", "bytes", "bytes32"], token_event_raw.data
                        )
                        token_event = InterchainTokenService.TokenSentWithData(
                            dtoken_id,
                            ddestination_chain,
                            ddestination_address,
                            Abi.decode(["uint256"], token_event_raw.topics[1])[0],
                            Abi.decode(["address"], token_event_raw.topics[2])[0],
                            ddata,
                            dsend_hash,
                        )
                except StopIteration:
                    token_event = None

                express_receive = random_bool(true_prob=0.25)
                if express_receive and token_event is not None:
                    self._express_receive(token_event, destination_chain)

                destination_gw.approveContractCall(Abi.encode(
                    ["string", "string", "address", "bytes32", "bytes32", "uint256"],
                    [source_chain_name, str(sender), Address(destination_address_str), event.topics[2], bytes.fromhex(tx.tx_hash[2:]), index]
                    ), command_id)

                callable = lambda: IAxelarExecutable(destination_address_str, chain=destination_chain).execute(
                    command_id,
                    source_chain_name,
                    str(sender),
                    payload,
                )
                if token_event is not None:
                    tx = self._execute_with_flow_limit(callable, destination_chain, token_event.tokenId, token_event.amount, 0)
                else:
                    tx = callable()
                self._last_relay_tx = tx
                self._command_counter += 1
            elif event.topics[0] == MockAxelarGateway.ContractCallWithToken.selector:
                sender = Abi.decode(["address"], event.topics[1])[0]
                destination_chain_name, destination_address_str, payload, symbol, amount = Abi.decode(
                    ["string", "string", "bytes", "string", "uint256"], event.data
                )
                destination_chain = chain2 if destination_chain_name == "chain2" else chain1
                destination_gw = self._gateways[destination_chain]
                source_chain_name = "chain1" if destination_chain_name == "chain2" else "chain2"
                command_id = self._command_counter.to_bytes(32, "big")

                try:
                    token_event_raw = next(
                        ev for ev in tx.raw_events
                        if len(ev.topics) > 0 and ev.topics[0] in {
                            InterchainTokenService.TokenSent.selector,
                            InterchainTokenService.TokenSentWithData.selector,
                        }
                    )
                    if token_event_raw.topics[0] == InterchainTokenService.TokenSent.selector:
                        dtoken_id, ddestination_chain, ddestination_address, dsend_hash = Abi.decode(
                            ["bytes32", "string", "bytes", "bytes32"], token_event_raw.data
                        )
                        token_event = InterchainTokenService.TokenSent(
                            dtoken_id,
                            ddestination_chain,
                            ddestination_address,
                            Abi.decode(["uint256"], token_event_raw.topics[1])[0],
                            dsend_hash,
                        )
                    else:
                        dtoken_id, ddestination_chain, ddestination_address, ddata, dsend_hash = Abi.decode(
                            ["bytes32", "string", "bytes", "bytes", "bytes32"], token_event_raw.data
                        )
                        token_event = InterchainTokenService.TokenSentWithData(
                            dtoken_id,
                            ddestination_chain,
                            ddestination_address,
                            Abi.decode(["uint256"], token_event_raw.topics[1])[0],
                            Abi.decode(["address"], token_event_raw.topics[2])[0],
                            ddata,
                            dsend_hash,
                        )
                except StopIteration:
                    token_event = None

                express_receive = random_bool(true_prob=0.25)
                if express_receive and token_event is not None:
                    self._express_receive(token_event, destination_chain)

                destination_gw.approveContractCallWithMint(Abi.encode(
                    ["string", "string", "address", "bytes32", "string", "uint256", "bytes32", "uint256"],
                    [source_chain_name, str(sender), Address(destination_address_str), event.topics[2], symbol, amount, bytes.fromhex(tx.tx_hash[2:]), index]
                    ), command_id)

                callable = lambda: IAxelarExecutable(destination_address_str, chain=destination_chain).executeWithToken(
                    command_id,
                    source_chain_name,
                    str(sender),
                    payload,
                    symbol,
                    amount,
                )
                if token_event is not None:
                    tx = self._execute_with_flow_limit(callable, destination_chain, token_event.tokenId, token_event.amount, 0)
                else:
                    tx = callable()
                self._last_relay_tx = tx
                self._command_counter += 1

    @staticmethod
    def _deploy_erc20(chain: Chain, token_manager: Address):
        name = random_string(3, 10, alphabet=string.ascii_lowercase)
        symbol = random_string(3, 3, alphabet=string.ascii_uppercase)
        decimals = random_int(6, 18)
        return InterchainTokenTest.deploy(name, symbol, decimals, token_manager, chain=chain)

    def _deploy_custom_canonical(self, service: InterchainTokenService, salt: bytes32) -> Tuple[str, str, int]:
        name = random_string(3, 10, alphabet=string.ascii_lowercase)
        symbol = random_string(3, 3, alphabet=string.ascii_uppercase)
        decimals = random_int(6, 18)

        service.deployCustomTokenManagerCanonical(
            salt,
            bytes(service.chain.accounts[0].address),
            name, symbol, decimals, 0,
        )
        token_id = service.getCustomTokenId(service.chain.accounts[0].address, salt)
        token_manager = TokenManagerCanonicalMock(
            service.getValidTokenManagerAddress(token_id),
            chain=service.chain,
        )

        self._balances[token_manager] = defaultdict(int)
        self._allowances[token_manager] = defaultdict(lambda: defaultdict(int))
        self._initial_mint(token_manager)
        return name, symbol, decimals

    def _deploy_custom_liquidity_pool(self, service: InterchainTokenService, salt: bytes32) -> Tuple[str, str, int]:
        token_id = service.getCustomTokenId(service.chain.accounts[0].address, salt)
        token_manager = service.getTokenManagerAddress(token_id)
        token = self._deploy_erc20(service.chain, token_manager)  # pyright: ignore reportGeneralTypeIssues
        pool = Account(random_address(), chain=token.chain)

        service.deployCustomTokenManagerLiquidityPool(
            salt,
            bytes(service.chain.accounts[0].address),
            token,
            pool,
        )

        # give infinite approval
        token.approve(token_manager, 2**256 - 1, from_=pool)

        # mint enought tokens to the pool
        token.mint(pool, 2**128)

        self._balances[token] = defaultdict(int)
        self._balances[token][pool] = 2**128
        self._allowances[token] = defaultdict(lambda: defaultdict(int))
        self._allowances[token][pool][Account(token_manager, chain=token.chain)] = 2**256 - 1
        self._initial_mint(token)
        return token.name(), token.symbol(), token.decimals()

    def _deploy_custom_lock_unlock(self, service: InterchainTokenService, salt: bytes32) -> Tuple[str, str, int]:
        token_id = service.getCustomTokenId(service.chain.accounts[0].address, salt)
        token_manager = service.getTokenManagerAddress(token_id)
        token = self._deploy_erc20(service.chain, token_manager)  # pyright: ignore reportGeneralTypeIssues

        service.deployCustomTokenManagerLockUnlock(
            salt,
            bytes(service.chain.accounts[0].address),
            token,
        )

        # mint enought tokens to the token manager
        token.mint(token_manager, 2**128)

        self._balances[token] = defaultdict(int)
        self._balances[token][Account(token_manager, chain=token.chain)] = 2**128
        self._allowances[token] = defaultdict(lambda: defaultdict(int))
        self._initial_mint(token)
        return token.name(), token.symbol(), token.decimals()

    def _deploy_custom_mint_burn(self, service: InterchainTokenService, salt: bytes32) -> Tuple[str, str, int]:
        token_id = service.getCustomTokenId(service.chain.accounts[0].address, salt)
        token_manager = service.getTokenManagerAddress(token_id)
        token = self._deploy_erc20(service.chain, token_manager)  # pyright: ignore reportGeneralTypeIssues

        service.deployCustomTokenManagerMintBurn(
            salt,
            bytes(service.chain.accounts[0].address),
            token,
        )

        self._balances[token] = defaultdict(int)
        self._allowances[token] = defaultdict(lambda: defaultdict(int))
        self._initial_mint(token)
        return token.name(), token.symbol(), token.decimals()

    def _deploy_canonical_pair(self, service: InterchainTokenService) -> None:
        token = self._deploy_erc20(service.chain, Address.ZERO)  # pyright: ignore reportGeneralTypeIssues
        token_id = service.getCanonicalTokenId(token)
        assert service.registerCanonicalTokenAndDeployRemoteCanonicalTokens(
            token,
            ["chain1" if service.chain == chain2 else "chain2"],
            [0],
        ).return_value == token_id
        token_manager = service.getValidTokenManagerAddress(token_id)
        token.setTokenManager(ITokenManager(token_manager, chain=token.chain))

        self._balances[token] = defaultdict(int)
        self._allowances[token] = defaultdict(lambda: defaultdict(int))
        self._initial_mint(token)

        # mint enought tokens to the token manager
        token.mint(token_manager, 2**128)
        self._balances[token][Account(token_manager, chain=token.chain)] = 2**128

        # address of the service on all chains is the same => token manager address is the same
        destination_token_manager = TokenManagerCanonicalMock(
            token_manager,
            chain=chain2 if service.chain == chain1 else chain1,
        )
        self._balances[destination_token_manager] = defaultdict(int)
        self._allowances[destination_token_manager] = defaultdict(lambda: defaultdict(int))
        self._initial_mint(destination_token_manager)

    def _deploy_pair(
        self,
        local_type: ITokenManagerType.TokenManagerType,
        remote_type: ITokenManagerType.TokenManagerType,
        local_service: InterchainTokenService,
    ):
        salt = random_bytes(32)
        token_id = local_service.getCustomTokenId(local_service.chain.accounts[0], salt)

        if local_type == ITokenManagerType.TokenManagerType.CANONICAL:
            name, symbol, decimals = self._deploy_custom_canonical(local_service, salt)
        elif local_type == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
            name, symbol, decimals = self._deploy_custom_liquidity_pool(local_service, salt)
        elif local_type == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
            name, symbol, decimals = self._deploy_custom_lock_unlock(local_service, salt)
        elif local_type == ITokenManagerType.TokenManagerType.MINT_BURN:
            name, symbol, decimals = self._deploy_custom_mint_burn(local_service, salt)
        else:
            raise Exception("Unknown type")

        admin = bytes(local_service.chain.accounts[0].address)
        remote_chain = chain2 if local_service.chain == chain1 else chain1

        if remote_type == ITokenManager.TokenManagerType.CANONICAL:
            token_manager = TokenManagerCanonicalMock(local_service.getTokenManagerAddress(token_id), chain=remote_chain)
            self._balances[token_manager] = defaultdict(int)
            self._allowances[token_manager] = defaultdict(lambda: defaultdict(int))

            params = local_service.getParamsCanonical(admin, name, symbol, decimals, 0)
        elif remote_type == ITokenManager.TokenManagerType.LIQUIDITY_POOL:
            token_manager = local_service.getTokenManagerAddress(token_id)
            token = InterchainTokenTest.deploy(name, symbol, decimals, token_manager, chain=remote_chain)
            self._balances[token] = defaultdict(int)
            self._allowances[token] = defaultdict(lambda: defaultdict(int))

            pool = Account(random_address(), chain=remote_chain)
            params = local_service.getParamsLiquidityPool(admin, token.address, pool.address)

            # give infinite approval
            token.approve(token_manager, 2**256 - 1, from_=pool)
            self._allowances[token][pool][Account(token_manager, chain=token.chain)] = 2**256 - 1

            # mint enought tokens to the pool
            token.mint(pool, 2**128)
            self._balances[token][pool] = 2**128
        elif remote_type == ITokenManager.TokenManagerType.LOCK_UNLOCK:
            token_manager = local_service.getTokenManagerAddress(token_id)
            token = InterchainTokenTest.deploy(name, symbol, decimals, token_manager, chain=remote_chain)
            self._balances[token] = defaultdict(int)
            self._allowances[token] = defaultdict(lambda: defaultdict(int))

            # mint enought tokens to the token manager
            token.mint(token_manager, 2**128)
            self._balances[token][Account(token_manager, chain=token.chain)] = 2**128

            params = local_service.getParamsLockUnlock(admin, token.address)
        elif remote_type == ITokenManager.TokenManagerType.MINT_BURN:
            token_manager = local_service.getTokenManagerAddress(token_id)
            token = InterchainTokenTest.deploy(name, symbol, decimals, token_manager, chain=remote_chain)
            self._balances[token] = defaultdict(int)
            self._allowances[token] = defaultdict(lambda: defaultdict(int))

            params = local_service.getParamsMintBurn(admin, token.address)
        else:
            raise Exception("Unknown type")

        local_service.deployRemoteCustomTokenManagers(
            salt,
            ["chain1" if remote_chain == chain1 else "chain2"],
            [remote_type],
            [params],
            [0],
        )
        remote_token = ITokenManager(token_manager, chain=remote_chain).tokenAddress()
        self._initial_mint(IERC20BurnableMintable(remote_token, chain=remote_chain))

    def _initial_mint(self, token: IERC20BurnableMintable) -> None:
        token_manager = InterchainToken(token).getTokenManager()
        limit = random_int(2**23, 2**25)
        token_manager.setFlowLimit(limit, from_=token_manager.admin())
        for a in token.chain.accounts:
            amount = random_int(0, 2**24 - 1)
            token.mint(a, amount)
            self._balances[InterchainToken(token)][a] += amount
            assert token.balanceOf(a) == self._balances[InterchainToken(token)][a]

    def pre_sequence(self) -> None:
        self._command_counter = 0
        self._last_relay_tx = None
        chain1.tx_callback = self._relay
        chain2.tx_callback = self._relay

        service1, gw1 = deploy_interchain_token_service(chain1, chain1.accounts[0])
        service2, gw2 = deploy_interchain_token_service(chain2, chain2.accounts[0])
        assert service1.address == service2.address

        self._services = {chain1: service1, chain2: service2}
        self._gateways = {chain1: gw1, chain2: gw2}
        self._payload_receivers = {
            chain1: PayloadReceiver.deploy(chain=chain1),
            chain2: PayloadReceiver.deploy(chain=chain2)
        }
        self._balances = {}
        self._allowances = {}
        self._flow_in_amounts = defaultdict(lambda: defaultdict(int))
        self._flow_out_amounts = defaultdict(lambda: defaultdict(int))

        # deploy one canonical pair LockUnlock/Canonical
        self._deploy_canonical_pair(random.choice([service1, service2]))

        # deploy all combinations of custom token managers
        all_types = ITokenManagerType.TokenManagerType.__members__.values()
        local_service = random.choice([service1, service2])
        for local_type in all_types:
            for remote_type in all_types:
                self._deploy_pair(local_type, remote_type, local_service)

        self.invariant_balances()
        self.invariant_allowances()

    @flow()
    def flow_mint(self) -> None:
        token = random.choice(list(self._balances.keys()))
        recipient = random_account(chain=token.chain)
        amount = random_int(0, 2**24 - 1)

        with may_revert() as e:
            IERC20BurnableMintable(token, chain=token.chain).mint(recipient, amount)

        if token.totalSupply() + amount >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[token][recipient] += amount

        logger.info(f"mint {amount} {token.symbol()} to {recipient.address}")

    @flow(weight=50)
    def flow_permit(self) -> None:
        token = random.choice(list(self._allowances.keys()))
        owner = random_account(chain=token.chain)
        spender = random_account(chain=token.chain)
        value = random_int(0, 2**256 - 1)

        permit = Permit(
            owner.address, spender.address, value, token.nonces(owner),
            token.chain.blocks["latest"].timestamp + 100_000
        )
        signature = owner.sign_structured(permit, Eip712Domain(
            name=token.name(),
            version="1",
            chainId=token.chain.chain_id,
            verifyingContract=token.address,
        ))

        token.permit(
            owner, spender, value, permit.deadline, signature[64], signature[:32],
            signature[32:64], from_=random_account(chain=token.chain)
        )
        self._allowances[token][owner][spender] = value

        logger.info(f"permit {value} {token.symbol()} to {spender.address}")

    @flow(weight=50)
    def flow_approve(self) -> None:
        token = random.choice(list(self._allowances.keys()))
        owner = random_account(chain=token.chain)
        spender = random_account(chain=token.chain)
        value = random_int(0, 2**256 - 1)

        token.approve(spender, value, from_=owner)
        self._allowances[token][owner][spender] = value

        logger.info(f"approve {value} {token.symbol()} to {spender.address}")

    @flow(weight=50)
    def flow_increase_allowance(self) -> None:
        token = random.choice(list(self._allowances.keys()))
        owner = random_account(chain=token.chain)
        spender = random_account(chain=token.chain)
        value = random_int(0, 2**256 - 1)

        with may_revert() as e:
            token.increaseAllowance(spender, value, from_=owner)

        if self._allowances[token][owner][spender] + value >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._allowances[token][owner][spender] += value

            logger.info(f"increase allowance {value} {token.symbol()} to {spender.address}")

    @flow(weight=50)
    def flow_decrease_allowance(self) -> None:
        token = random.choice(list(self._allowances.keys()))
        owner = random_account(chain=token.chain)
        spender = random_account(chain=token.chain)
        value = random_int(0, 2**256 - 1)

        with may_revert() as e:
            token.decreaseAllowance(spender, value, from_=owner)

        if self._allowances[token][owner][spender] - value < 0:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._allowances[token][owner][spender] -= value

            logger.info(f"decrease allowance {value} {token.symbol()} to {spender.address}")

    @flow(weight=50)
    def flow_transfer(self) -> None:
        token = random.choice(list(self._balances.keys()))
        sender = random_account(chain=token.chain)
        recipient = random_account(chain=token.chain)
        insufficient_balance = random_bool(true_prob=0.2)

        if insufficient_balance:
            amount = random_int(self._balances[token][sender] + 1, 2**256 - 1)
        else:
            amount = random_int(0, self._balances[token][sender])

        with may_revert() as e:
            token.transfer(recipient, amount, from_=sender)

        if insufficient_balance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[token][sender] -= amount
            self._balances[token][recipient] += amount

            logger.info(f"transfer {amount} {token.symbol()} from {sender.address} to {recipient.address}")

    @flow(weight=50)
    def flow_transfer_from(self) -> None:
        token = random.choice(list(self._balances.keys()))
        sender = random_account(chain=token.chain)
        recipient = random_account(chain=token.chain)
        executor = random_account(chain=token.chain)
        insufficient_allowance = random_bool(true_prob=0.15)

        if insufficient_allowance:
            amount = random_int(self._allowances[token][sender][executor] + 1, 2**256 - 1)
            insufficient_balance = False
        else:
            insufficient_balance = random_bool(true_prob=0.15)

            if insufficient_balance:
                amount = random_int(self._balances[token][sender] + 1, 2**256 - 1)
                token.approve(executor, amount, from_=sender)
                self._allowances[token][sender][executor] = amount
            else:
                # set allowance to avoid zero transfers
                new_allowance = random_int(0, 2**24 - 1, edge_values_prob=0.2)
                token.approve(executor, new_allowance, from_=sender)
                self._allowances[token][sender][executor] = new_allowance
                amount = random_int(0, min(self._balances[token][sender], self._allowances[token][sender][executor]))

        with may_revert() as e:
            token.transferFrom(sender, recipient, amount, from_=executor)

        if insufficient_allowance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        elif insufficient_balance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[token][sender] -= amount
            self._balances[token][recipient] += amount
            self._allowances[token][sender][executor] -= amount

            logger.info(f"transfer {amount} {token.symbol()} from {sender.address} to {recipient.address} by {executor.address}")

    @flow()
    def flow_interchain_transfer(self) -> None:
        token = random.choice(list(self._balances.keys()))
        token_manager = token.getTokenManager()
        destination_chain = chain1 if token.chain == chain2 else chain2
        sender = random_account(chain=token.chain)

        send_metadata = random_bool(true_prob=0.1)
        if send_metadata:
            recipient = self._payload_receivers[destination_chain]
            metadata = random_bytes(1, 100)
        else:
            recipient = random_account(chain=destination_chain)
            metadata = b""

        insufficient_balance = random_bool(true_prob=0.1)
        if insufficient_balance:
            amount = random_int(self._balances[token][sender] + 1, 2**256 - 1)
        else:
            amount = random_int(0, self._balances[token][sender])

        # ERC20 implementation does not allow minting 0 tokens
        if amount == 0:
            return

        token_id = ITokenManagerProxy(token.getTokenManager(), chain=token.chain).tokenId()
        destination_token_manager = ITokenManager(self._services[destination_chain].getValidTokenManagerAddress(token_id), chain=destination_chain)
        destination_token = InterchainTokenTest(
            destination_token_manager.tokenAddress(),
            chain=destination_chain,
        )

        if token_manager.getFlowLimit() < amount:
            token_manager.setFlowLimit(amount, from_=token_manager.admin())
        if destination_token_manager.getFlowLimit() < amount:
            destination_token_manager.setFlowLimit(amount, from_=destination_token_manager.admin())

        with may_revert() as e:
            callable = lambda: token.interchainTransfer(
                "chain1" if destination_chain == chain1 else "chain2",
                bytes(recipient.address),
                amount,
                metadata,
                from_=sender,
            )
            tx = self._execute_with_flow_limit(callable, token.chain, token_id, 0, amount)

        if token_manager.requiresApproval() and self._allowances[token][sender][token_manager] + amount >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        elif insufficient_balance:
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.CANONICAL:
                assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
            else:
                assert e.value == TokenTransferFailed()
            assert self._allowances[token][sender][token_manager] + amount < 2 ** 256 or not token_manager.requiresApproval()
        else:
            assert e.value is None
            assert self._allowances[token][sender][token_manager] + amount < 2 ** 256 or not token_manager.requiresApproval()
            self._balances[token][sender] -= amount
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved to the pool
                pool = TokenManagerLiquidityPool(token_manager, chain=token.chain).liquidityPool()
                self._balances[token][Account(pool, chain=token.chain)] += amount
            elif token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[token][token_manager] += amount
            # in other cases tokens are burned

            self._balances[destination_token][recipient] += amount
            if destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved from the pool
                pool = TokenManagerLiquidityPool(destination_token_manager, chain=destination_chain).liquidityPool()
                self._balances[destination_token][Account(pool, chain=destination_chain)] -= amount
            elif destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[destination_token][destination_token_manager] -= amount
            # in other cases tokens are minted

            if send_metadata:
                assert self._payload_receivers[destination_chain].lastPayload() == metadata

            self._flow_out_amounts[token_manager][tx.block.timestamp // (6 * 60 * 60)] += amount
            assert self._last_relay_tx is not None
            self._flow_in_amounts[destination_token_manager][self._last_relay_tx.block.timestamp // (6 * 60 * 60)] += amount

            logger.info(f"interchain transfer {amount} {token.symbol()} from {sender.address} chain{token.chain.chain_id} to {recipient.address} chain{destination_chain.chain_id}")

    @flow()
    def flow_interchain_transfer_from(self) -> None:
        token = random.choice(list(self._balances.keys()))
        token_manager = token.getTokenManager()
        destination_chain = chain1 if token.chain == chain2 else chain2
        sender = random_account(chain=token.chain)
        executor = random_account(chain=token.chain)

        send_metadata = random_bool(true_prob=0.1)
        if send_metadata:
            recipient = self._payload_receivers[destination_chain]
            metadata = random_bytes(1, 100)
        else:
            recipient = random_account(chain=destination_chain)
            metadata = b""

        insufficient_allowance = random_bool(true_prob=0.1)

        if insufficient_allowance:
            amount = random_int(self._allowances[token][sender][executor] + 1, 2**256 - 1)
            insufficient_balance = False
        else:
            insufficient_balance = random_bool(true_prob=0.1)

            if insufficient_balance:
                amount = random_int(self._balances[token][sender] + 1, 2**256 - 1)
                token.approve(executor, amount, from_=sender)
                self._allowances[token][sender][executor] = amount
            else:
                # set allowance to avoid zero transfers
                new_allowance = random_int(0, 2**24 - 1, edge_values_prob=0.2)
                token.approve(executor, new_allowance, from_=sender)
                self._allowances[token][sender][executor] = new_allowance
                amount = random_int(0, min(self._balances[token][sender], self._allowances[token][sender][executor]))

        # ERC20 implementation does not allow minting 0 tokens
        if amount == 0:
            return

        token_id = ITokenManagerProxy(token.getTokenManager(), chain=token.chain).tokenId()
        destination_token_manager = ITokenManager(self._services[destination_chain].getValidTokenManagerAddress(token_id), chain=destination_chain)
        destination_token = InterchainTokenTest(
            destination_token_manager.tokenAddress(),
            chain=destination_chain,
        )

        if token_manager.getFlowLimit() < amount:
            token_manager.setFlowLimit(amount, from_=token_manager.admin())
        if destination_token_manager.getFlowLimit() < amount:
            destination_token_manager.setFlowLimit(amount, from_=destination_token_manager.admin())

        with may_revert() as e:
            callable = lambda: token.interchainTransferFrom(
                sender,
                "chain1" if destination_chain == chain1 else "chain2",
                bytes(recipient.address),
                amount,
                metadata,
                from_=executor,
            )
            tx = self._execute_with_flow_limit(callable, token.chain, token_id, 0, amount)

        if insufficient_allowance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        elif token_manager.requiresApproval() and self._allowances[token][sender][token_manager] + amount >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        elif insufficient_balance:
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.CANONICAL:
                assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
            else:
                assert e.value == TokenTransferFailed()
            assert self._allowances[token][sender][token_manager] + amount < 2 ** 256 or not token_manager.requiresApproval()
        else:
            assert e.value is None
            assert self._allowances[token][sender][token_manager] + amount < 2 ** 256 or not token_manager.requiresApproval()
            self._allowances[token][sender][executor] -= amount
            self._balances[token][sender] -= amount
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved to the pool
                pool = TokenManagerLiquidityPool(token_manager, chain=token.chain).liquidityPool()
                self._balances[token][Account(pool, chain=token.chain)] += amount
            elif token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[token][token_manager] += amount
            # in other cases tokens are burned

            self._balances[destination_token][recipient] += amount
            if destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved from the pool
                pool = TokenManagerLiquidityPool(destination_token_manager, chain=destination_chain).liquidityPool()
                self._balances[destination_token][Account(pool, chain=destination_chain)] -= amount
            elif destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[destination_token][destination_token_manager] -= amount
            # in other cases tokens are minted

            if send_metadata:
                assert self._payload_receivers[destination_chain].lastPayload() == metadata

            self._flow_out_amounts[token_manager][tx.block.timestamp // (6 * 60 * 60)] += amount
            assert self._last_relay_tx is not None
            self._flow_in_amounts[destination_token_manager][self._last_relay_tx.block.timestamp // (6 * 60 * 60)] += amount

            logger.info(f"interchain transfer {amount} {token.symbol()} from {sender.address} chain{token.chain.chain_id} to {recipient.address} chain{destination_chain.chain_id} by {executor.address}")

    @flow()
    def flow_interchain_send_token(self) -> None:
        token = random.choice(list(self._balances.keys()))
        token_manager = token.getTokenManager()
        destination_chain = chain1 if token.chain == chain2 else chain2
        sender = random_account(chain=token.chain)

        send_metadata = random_bool(true_prob=0.1)
        if send_metadata:
            recipient = self._payload_receivers[destination_chain]
            metadata = random_bytes(1, 100)
        else:
            recipient = random_account(chain=destination_chain)
            metadata = b""

        insufficient_allowance = random_bool(true_prob=0.1) and token_manager.typeOf() != ITokenManagerType.TokenManagerType.CANONICAL

        if insufficient_allowance:
            amount = random_int(self._allowances[token][sender][token_manager] + 1, 2**256 - 1)
            insufficient_balance = False
        else:
            insufficient_balance = random_bool(true_prob=0.1)

            if insufficient_balance:
                amount = random_int(self._balances[token][sender] + 1, 2**256 - 1)
                token.approve(token_manager, amount, from_=sender)
                self._allowances[token][sender][token_manager] = amount
            else:
                # set allowance to avoid zero transfers
                new_allowance = random_int(0, 2**24 - 1, edge_values_prob=0.2)
                token.approve(token_manager, new_allowance, from_=sender)
                self._allowances[token][sender][token_manager] = new_allowance
                amount = random_int(0, min(self._balances[token][sender], self._allowances[token][sender][token_manager]))

        # ERC20 implementation does not allow minting 0 tokens
        if amount == 0:
            return

        token_id = ITokenManagerProxy(token.getTokenManager(), chain=token.chain).tokenId()
        destination_token_manager = ITokenManager(self._services[destination_chain].getValidTokenManagerAddress(token_id), chain=destination_chain)
        destination_token = InterchainTokenTest(
            destination_token_manager.tokenAddress(),
            chain=destination_chain,
        )

        if token_manager.getFlowLimit() < amount:
            token_manager.setFlowLimit(amount, from_=token_manager.admin())
        if destination_token_manager.getFlowLimit() < amount:
            destination_token_manager.setFlowLimit(amount, from_=destination_token_manager.admin())

        with may_revert() as e:
            if send_metadata:
                callable = lambda: token_manager.callContractWithInterchainToken(
                    "chain1" if destination_chain == chain1 else "chain2",
                    bytes(recipient.address),
                    amount,
                    metadata,
                    from_=sender,
                )
            else:
                callable = lambda: token_manager.sendToken(
                    "chain1" if destination_chain == chain1 else "chain2",
                    bytes(recipient.address),
                    amount,
                    from_=sender,
                )
            tx = self._execute_with_flow_limit(callable, token.chain, token_id, 0, amount)

        if insufficient_allowance:
            assert e.value == TokenTransferFailed()
        elif insufficient_balance:
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.CANONICAL:
                assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
            else:
                assert e.value == TokenTransferFailed()
        else:
            assert e.value is None
            if token_manager.typeOf() not in {ITokenManagerType.TokenManagerType.CANONICAL, ITokenManagerType.TokenManagerType.MINT_BURN}:
                self._allowances[token][sender][token_manager] -= amount
            self._balances[token][sender] -= amount
            if token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved to the pool
                pool = TokenManagerLiquidityPool(token_manager, chain=token.chain).liquidityPool()
                self._balances[token][Account(pool, chain=token.chain)] += amount
            elif token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[token][token_manager] += amount
            # in other cases tokens are burned

            self._balances[destination_token][recipient] += amount
            if destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LIQUIDITY_POOL:
                # tokens moved from the pool
                pool = TokenManagerLiquidityPool(destination_token_manager, chain=destination_chain).liquidityPool()
                self._balances[destination_token][Account(pool, chain=destination_chain)] -= amount
            elif destination_token_manager.typeOf() == ITokenManagerType.TokenManagerType.LOCK_UNLOCK:
                self._balances[destination_token][destination_token_manager] -= amount
            # in other cases tokens are minted

            if send_metadata:
                assert self._payload_receivers[destination_chain].lastPayload() == metadata

            self._flow_out_amounts[token_manager][tx.block.timestamp // (6 * 60 * 60)] += amount
            assert self._last_relay_tx is not None
            self._flow_in_amounts[destination_token_manager][self._last_relay_tx.block.timestamp // (6 * 60 * 60)] += amount

            logger.info(f"interchain send token {amount} {token.symbol()} from {sender.address} chain{token.chain.chain_id} to {recipient.address} chain{destination_chain.chain_id}")


    @invariant(period=100)
    def invariant_balances(self) -> None:
        for token in self._balances.keys():
            sum = 0
            for a, balance in self._balances[token].items():
                assert token.balanceOf(a) == balance
                sum += balance
            assert token.totalSupply() == sum

    @invariant(period=100)
    def invariant_allowances(self) -> None:
        for token in self._allowances.keys():
            for owner, allowances in self._allowances[token].items():
                for spender, allowance in allowances.items():
                    assert token.allowance(owner, spender) == allowance

    @invariant(period=100)
    def invariant_flow_amounts(self) -> None:
        for token in self._balances.keys():
            token_manager = token.getTokenManager()
            latest_block = token_manager.chain.blocks["latest"]
            assert token_manager.getFlowInAmount(block=latest_block.number) == self._flow_in_amounts[token_manager][latest_block.timestamp // (6 * 60 * 60)]
            assert token_manager.getFlowOutAmount(block=latest_block.number) == self._flow_out_amounts[token_manager][latest_block.timestamp // (6 * 60 * 60)]


@chain1.connect(chain_id=1)
@chain2.connect(chain_id=2)
def test_interchain_fuzz():
    seed = random_bytes(32)
    logger.error(f"seed: {seed.hex()}")
    random.seed(seed)
    chain1.set_default_accounts(chain1.accounts[0])
    chain2.set_default_accounts(chain2.accounts[0])
    InterchainTokenFuzzTest().run(20, 10_000)
