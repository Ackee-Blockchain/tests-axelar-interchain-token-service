import logging
import random
from collections import defaultdict
from typing import Callable, Dict, NamedTuple
from wake.testing import *
from wake.testing.fuzzing import *
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.interfaces.IAxelarExecutable import IAxelarExecutable
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.interfaces.IAxelarExpressExecutable import IAxelarExpressExecutable
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.interfaces.IAxelarGateway import IAxelarGateway
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.interfaces.IERC20 import IERC20
from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.test.mocks.MockGateway import MockGateway
from pytypes.sourcev2.contracts.InterchainTokenFactory import InterchainTokenFactory

from pytypes.sourcev2.contracts.InterchainTokenService import InterchainTokenService
from pytypes.sourcev2.contracts.TokenHandler import TokenHandler
from pytypes.sourcev2.contracts.interchaintoken.InterchainToken import InterchainToken
from pytypes.sourcev2.contracts.interfaces.IERC20Named import IERC20Named
from pytypes.sourcev2.contracts.proxies.InterchainProxy import InterchainProxy
from pytypes.sourcev2.contracts.proxies.TokenManagerProxy import TokenManagerProxy
from pytypes.sourcev2.contracts.tokenmanager.TokenManager import TokenManager
from pytypes.sourcev2.contracts.utils.InterchainTokenDeployer import InterchainTokenDeployer
from pytypes.sourcev2.contracts.utils.TokenManagerDeployer import TokenManagerDeployer
from pytypes.tests.Create3 import Create3
from pytypes.tests.IStatera import IStatera

from pytypes.weird.Approval import ApprovalRaceToken
from pytypes.weird.ApprovalToZero import ApprovalToZeroToken
from pytypes.weird.DaiPermit import DaiPermit
from pytypes.weird.HighDecimals import HighDecimalToken
from pytypes.weird.LowDecimals import LowDecimalToken
from pytypes.weird.MissingReturns import MissingReturnToken
from pytypes.weird.NoRevert import NoRevertToken
from pytypes.weird.RevertToZero import RevertToZeroToken
from pytypes.weird.Uint96 import Uint96ERC20


weird_tokens: List[Callable[[int, Chain], Address]] = [
    lambda sup, chain: ApprovalRaceToken.deploy(sup, chain=chain).address,
    lambda sup, chain: ApprovalToZeroToken.deploy(sup, chain=chain).address,
    lambda sup, chain: DaiPermit.deploy(sup, chain=chain).address,
    lambda sup, chain: HighDecimalToken.deploy(sup, chain=chain).address,
    lambda sup, chain: LowDecimalToken.deploy(sup, chain=chain).address,
    lambda sup, chain: MissingReturnToken.deploy(sup, chain=chain).address,
    lambda sup, chain: NoRevertToken.deploy(sup, chain=chain).address,
    lambda sup, chain: RevertToZeroToken.deploy(sup, chain=chain).address,
    lambda sup, chain: Uint96ERC20.deploy(sup, chain=chain).address,
]


chain1 = Chain()
chain2 = Chain()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

gateway_tokens = [
    Address("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), # usdc
    Address("0xdac17f958d2ee523a2206206994597c13d831ec7"), # usdt
    Address("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"), # bnb
    Address("0x6b175474e89094c44da98b954eedeac495271d0f"), # dai
    Address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"), # weth
    Address("0x80fB784B7eD66730e8b1DBd9820aFD29931aab03"), # lend
    Address("0xaba8cac6866b83ae4eec97dd07ed254282f6ad8a"), # yamv2
    Address("0xdb25f211ab05b1c97d595516f45794528a807ad8"), # eurs
    Address("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"), # uni
]

other_tokens = [
    Address("0x514910771af9ca656af840dff83e8264ecf986ca"),  # link
    #Address("0x5a98fcbea516cf06857215779fd812ca3bef1b32"), # ldo (mint issue)
    Address("0xc944e90c64b2c07662a292be6244bdf05cda44a7"),  # grt
    Address("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9"),  # aave
    #Address("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"), # mkr (symbol decoding issue)
]

fee_on_transfer_tokens = [
    Address("0xa7DE087329BFcda5639247F96140f9DAbe3DeED1"), # sta (fee on transfer)
]


class Deployment(NamedTuple):
    gw: MockGateway
    its: InterchainTokenService
    factory: InterchainTokenFactory


class ItsFuzzTest(FuzzTest):
    deployments: Dict[Chain, Deployment]
    token_ids: Dict[Chain, List[bytes32]]
    interchain_tokens: Dict[Chain, List[InterchainToken]]

    balances: Dict[IERC20, Dict[Account, int]]

    def _deploy(self, deployer: Account, chain: Chain):
        create3 = Create3.deploy(chain=chain)
        gw = MockGateway.deploy(chain=chain)

        for a in gateway_tokens:
            t = IERC20Named(a, chain=chain)
            gw.deployToken(
                abi.encode(t.name(), t.symbol(), t.decimals(), uint256(0), a, uint256(uint256.max)),
                random_bytes(32),
            )

        its = create3.getAddress(keccak256(f"its{chain.chain_id}".encode()))
        interchain_token_factory = create3.getAddress(keccak256(f"interchain_token_factory{chain.chain_id}".encode()))
        token_manager_deployer = TokenManagerDeployer.deploy(chain=chain)
        interchain_token_deployer = InterchainTokenDeployer.deploy(
            InterchainToken.deploy(its, chain=chain),
            chain=chain,
        )
        token_manager = TokenManager.deploy(its, chain=chain)
        token_handler = TokenHandler.deploy(gw, chain=chain)

        impl = InterchainTokenService.deploy(
            token_manager_deployer,
            interchain_token_deployer,
            gw,
            Address(1),
            interchain_token_factory,
            f"chain{chain.chain_id}",
            token_manager,
            token_handler,
            chain=chain,
        )
        assert its == create3.deploy_(
            InterchainProxy.get_creation_code() + abi.encode(impl, deployer, b""),
            keccak256(f"its{chain.chain_id}".encode()),
        ).return_value
        impl = InterchainTokenFactory.deploy(its, chain=chain)
        assert interchain_token_factory == create3.deploy_(
            InterchainProxy.get_creation_code() + abi.encode(impl, deployer, b""),
            keccak256(f"interchain_token_factory{chain.chain_id}".encode()),
        ).return_value

        self.deployments[chain] = Deployment(
            MockGateway(gw, chain=chain),
            InterchainTokenService(its, chain=chain),
            InterchainTokenFactory(interchain_token_factory, chain=chain),
        )

    def _setup_canonical_gw_tokens(self, chain: Chain):
        d = self.deployments[chain]
        for a in gateway_tokens:
            t = IERC20Named(a, chain=chain)
            token_id = d.factory.registerGatewayToken(
                keccak256(t.symbol().encode()), t.symbol()
            ).return_value
            self.token_ids[chain].append(token_id)

            mint_erc20(t, d.gw, 10_000_000)

    def _setup_balances(self, chain: Chain):
        d = self.deployments[chain]
        for token_id in self.token_ids[chain]:
            t = IERC20(d.its.validTokenAddress(token_id), chain=chain)
            self.balances[t] = defaultdict(int)
            for acc in chain.accounts:
                self.balances[t][acc] = t.balanceOf(acc)
            self.balances[t][d.gw] = t.balanceOf(d.gw)
            self.balances[t][d.its] = t.balanceOf(d.its)

    def _relay(self, tx: TransactionAbc):
        other_chain = chain1 if tx.chain == chain2 else chain2
        other_gw = self.deployments[other_chain].gw
        for i, e in enumerate(tx.events):
            if isinstance(e, MockGateway.ContractCall):
                command_id = random_bytes(32)
                message_type = abi.decode(e.payload, [uint256])

                if message_type == 0 and random.random() < 0.5:
                    _, token_id, _, _, amount = abi.decode(e.payload, [uint256, bytes32, bytes, bytes, uint256])
                    t = IERC20Named(self.deployments[other_chain].its.validTokenAddress(token_id), chain=other_chain)
                    express_executor = random_account(chain=other_chain)
                    t.approve(self.deployments[other_chain].its, amount, from_=express_executor)
                    mint_erc20(t, express_executor, amount)

                    if t.address == fee_on_transfer_tokens[0]:
                        amount -= IStatera(t, chain=other_chain).cut(amount)
                    self.balances[t][express_executor] += amount

                    IAxelarExpressExecutable(e.destinationContractAddress, chain=other_chain).expressExecute(
                        command_id, f"chain{tx.chain.chain_id}", str(e.sender), e.payload, from_=express_executor
                    )

                other_gw.approveContractCall(
                    abi.encode(
                        f"chain{tx.chain.chain_id}", str(e.sender),
                        Address(e.destinationContractAddress), e.payloadHash,
                        bytes32.fromhex(tx.tx_hash[2:]), uint256(i)
                    ),
                    command_id,
                )
                IAxelarExecutable(e.destinationContractAddress, chain=other_chain).execute(
                    command_id, f"chain{tx.chain.chain_id}",
                    str(e.sender), e.payload, from_=random_account(chain=other_chain)
                )
            elif isinstance(e, MockGateway.ContractCallWithToken):
                command_id = random_bytes(32)
                message_type = abi.decode(e.payload, [uint256])

                if message_type == 0 and random.random() < 0.5:
                    _, token_id, _, _, amount = abi.decode(e.payload, [uint256, bytes32, bytes, bytes, uint256])
                    t = IERC20Named(self.deployments[other_chain].its.validTokenAddress(token_id), chain=other_chain)
                    express_executor = random_account(chain=other_chain)
                    t.approve(self.deployments[other_chain].its, amount, from_=express_executor)
                    mint_erc20(t, express_executor, amount)

                    if t.address == fee_on_transfer_tokens[0]:
                        amount -= IStatera(t, chain=other_chain).cut(amount)
                    self.balances[t][express_executor] += amount

                    IAxelarExpressExecutable(e.destinationContractAddress, chain=other_chain).expressExecuteWithToken(
                        command_id, f"chain{tx.chain.chain_id}", str(e.sender), e.payload, e.symbol, e.amount, from_=express_executor
                    )

                other_gw.approveContractCallWithMint(
                    abi.encode(
                        f"chain{tx.chain.chain_id}", str(e.sender),
                        Address(e.destinationContractAddress), e.payloadHash,
                        e.symbol, e.amount, bytes32.fromhex(tx.tx_hash[2:]), uint256(i)
                    ),
                    command_id,
                )
                IAxelarExecutable(e.destinationContractAddress, chain=other_chain).executeWithToken(
                    command_id, f"chain{tx.chain.chain_id}",
                    str(e.sender), e.payload, e.symbol, e.amount,
                    from_=random_account(chain=other_chain),
                )

    def pre_sequence(self) -> None:
        self.deployments = {}
        self.balances = {}
        self.token_ids = {chain1: [], chain2: []}
        self.interchain_tokens = {chain1: [], chain2: []}

        chain1.default_tx_account = random_account(chain=chain1)
        self._deploy(chain1.default_tx_account, chain1)

        chain2.default_tx_account = random_account(chain=chain2)
        self._deploy(chain2.default_tx_account, chain2)

        self.deployments[chain1].its.setTrustedAddress(
            "chain2", str(self.deployments[chain2].its.address)
        )
        self.deployments[chain2].its.setTrustedAddress(
            "chain1", str(self.deployments[chain1].its.address)
        )

        self._setup_canonical_gw_tokens(chain1)
        self._setup_canonical_gw_tokens(chain2)

        self._setup_balances(chain1)
        self._setup_balances(chain2)

        chain1.tx_callback = self._relay
        chain2.tx_callback = self._relay

    @flow(max_times=len(other_tokens * 2))
    def flow_register_canonical_token(self):
        chain = random.choice([chain1, chain2])
        d = self.deployments[chain]

        available_tokens = [t for t in other_tokens if d.factory.canonicalInterchainTokenId(t) not in self.token_ids[chain]]
        if len(available_tokens) == 0:
            return
        token = random.choice(available_tokens)

        token_id = d.factory.registerCanonicalInterchainToken(
            token, from_=random_account(chain=chain)
        ).return_value
        self.token_ids[chain].append(token_id)

        t = IERC20(token, chain=chain)
        token_manager = TokenManagerProxy(d.its.tokenManagerAddress(token_id), chain=chain)
        mint_erc20(t, token_manager, 10_000_000)

        if t not in self.balances:
            self.balances[t] = defaultdict(int)
        self.balances[t][token_manager] += 10_000_000
        for acc in chain.accounts:
            self.balances[t][acc] = t.balanceOf(acc)

        # other chain
        other_chain = chain1 if chain == chain2 else chain2
        assert d.factory.deployRemoteCanonicalInterchainToken(
            f"chain{chain.chain_id}", token, f"chain{other_chain.chain_id}", 0, from_=random_account(chain=chain)
        ).return_value == token_id

        other_token = self.deployments[other_chain].its.validTokenAddress(token_id)
        t = InterchainToken(other_token, chain=other_chain)

        if t not in self.balances:
            self.balances[t] = defaultdict(int)
        for acc in other_chain.accounts:
            self.balances[t][acc] = t.balanceOf(acc)

        self.interchain_tokens[other_chain].append(t)

    @flow()
    def flow_deploy_interchain_token(self):
        chain = random.choice([chain1, chain2])
        d = self.deployments[chain]

        salt = random_bytes(32)
        name = random_string(5, 7)
        symbol = random_string(3, 3, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        sender = random_account(chain=chain)
        token_id = d.its.deployInterchainToken(
            salt, "", name, symbol, 18, b"", 0, from_=sender
        ).return_value

        other_chain = chain1 if chain == chain2 else chain2

        if random.random() < 0.5:
            assert self.deployments[other_chain].its.deployInterchainToken(
                salt, "", name, symbol, 18, b"", 0, from_=sender.address
            ).return_value == token_id
        else:
            assert d.its.deployInterchainToken(
                salt, f"chain{other_chain.chain_id}", name, symbol, 18, b"", 0, from_=sender
            ).return_value == token_id

        self.token_ids[chain].append(token_id)
        t = IERC20(d.its.validTokenAddress(token_id), chain=chain)
        if t not in self.balances:
            self.balances[t] = defaultdict(int)
            for acc in chain.accounts:
                self.balances[t][acc] = t.balanceOf(acc)

        self.token_ids[other_chain].append(token_id)
        t = IERC20(self.deployments[other_chain].its.validTokenAddress(token_id), chain=other_chain)
        if t not in self.balances:
            self.balances[t] = defaultdict(int)
            for acc in other_chain.accounts:
                self.balances[t][acc] = t.balanceOf(acc)

        self.interchain_tokens[chain].append(
            InterchainToken(d.its.validTokenAddress(token_id), chain=chain)
        )
        self.interchain_tokens[other_chain].append(
            InterchainToken(self.deployments[other_chain].its.validTokenAddress(token_id), chain=other_chain)
        )

    @flow(max_times=30)
    def flow_deploy_token_manager(self):
        chain = random.choice([chain1, chain2])
        other_chain = chain1 if chain == chain2 else chain2
        d = self.deployments[chain]
        token_manager_type = random.choice([
            InterchainTokenService.TokenManagerType.GATEWAY,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
        ])

        if token_manager_type == InterchainTokenService.TokenManagerType.LOCK_UNLOCK:
            if random.random() < 0.3:
                source_token = random.choice(other_tokens)
                dest_token = source_token
            else:
                total_supply = random_int(1_000_000, 10_000_000)
                source_token = random.choice(weird_tokens)(total_supply, chain)
                dest_token = random.choice(weird_tokens)(total_supply, other_chain)
        elif token_manager_type == InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE:
            source_token = random.choice(fee_on_transfer_tokens)
            dest_token = source_token
        else:
            source_token = random.choice(gateway_tokens)
            dest_token = source_token

        deployer = random_account(chain=chain).address
        salt = random_bytes(32)
        token_id = d.its.deployTokenManager(
            salt, "", token_manager_type, abi.encode(b"", source_token), 0, from_=deployer
        ).return_value

        assert d.its.deployTokenManager(
            salt, f"chain{other_chain.chain_id}", token_manager_type, abi.encode(b"", dest_token), 0, from_=deployer
        ).return_value == token_id

        if token_manager_type in {
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
        }:
            source_token_manager = TokenManagerProxy(d.its.tokenManagerAddress(token_id), chain=chain)
            dest_token_manager = TokenManagerProxy(
                self.deployments[other_chain].its.tokenManagerAddress(token_id), chain=other_chain
            )
            mint_erc20(IERC20(source_token, chain=chain), source_token_manager, 10_000_000)
            mint_erc20(IERC20(dest_token, chain=other_chain), dest_token_manager, 10_000_000)

        self.token_ids[chain].append(token_id)
        t = IERC20(d.its.validTokenAddress(token_id), chain=chain)
        if t not in self.balances:
            self.balances[t] = defaultdict(int)
            for acc in chain.accounts:
                self.balances[t][acc] = t.balanceOf(acc)

        self.token_ids[other_chain].append(token_id)
        t = IERC20(self.deployments[other_chain].its.validTokenAddress(token_id), chain=other_chain)
        if t not in self.balances:
            self.balances[t] = defaultdict(int)
            for acc in other_chain.accounts:
                self.balances[t][acc] = t.balanceOf(acc)

        if token_manager_type in {
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
        }:
            self.balances[IERC20(source_token, chain=chain)][source_token_manager] += 10_000_000
            self.balances[IERC20(dest_token, chain=other_chain)][dest_token_manager] += 10_000_000

    @flow()
    def flow_token_interchain_transfer(self):
        chain = random.choice([chain1, chain2])
        other_chain = chain1 if chain == chain2 else chain2
        if len(self.interchain_tokens[chain]) == 0:
            return

        token = random.choice(self.interchain_tokens[chain])
        token_id = token.interchainTokenId()
        sender = random_account(chain=chain)
        recipient = random_address()
        amount = random_int(0, 1_000, edge_values_prob=0.15)
        mint_erc20(token, sender, amount)

        tx = token.interchainTransfer(
            f"chain{other_chain.chain_id}", bytes(recipient), amount, b"", from_=sender
        )

        # source token manager is mint-burn

        dest_its = self.deployments[other_chain].its
        dest_token = IERC20(dest_its.validTokenAddress(token_id), chain=other_chain)
        dest_token_manager = TokenManagerProxy(dest_its.tokenManagerAddress(token_id), chain=other_chain)
        if dest_token_manager.implementationType() in {
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
        }:
            self.balances[dest_token][dest_token_manager] -= amount
        elif dest_token_manager.implementationType() == InterchainTokenService.TokenManagerType.GATEWAY:
            self.balances[dest_token][self.deployments[other_chain].gw] -= amount

        if TokenManagerProxy(dest_its.tokenManagerAddress(token_id), chain=other_chain).implementationType() == InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE:
            amount -= IStatera(dest_token, chain=other_chain).cut(amount)

        self.balances[dest_token][Account(recipient, chain=other_chain)] += amount

        logger.info(f"Transferred {amount} {token.symbol()} from {chain.chain_id} to {other_chain.chain_id}")

    @flow()
    def flow_token_interchain_transfer_from(self):
        chain = random.choice([chain1, chain2])
        other_chain = chain1 if chain == chain2 else chain2
        if len(self.interchain_tokens[chain]) == 0:
            return

        token = random.choice(self.interchain_tokens[chain])
        token_id = token.interchainTokenId()
        owner = random_account(chain=chain)
        spender = random_account(chain=chain)
        recipient = random_address()
        amount = random_int(0, 1_000, edge_values_prob=0.15)
        mint_erc20(token, owner, amount)
        token.approve(spender, amount, from_=owner)

        dest_its = self.deployments[other_chain].its
        dest_token = IERC20(dest_its.validTokenAddress(token_id), chain=other_chain)
        dest_token_manager = TokenManagerProxy(dest_its.tokenManagerAddress(token_id), chain=other_chain)

        tx = token.interchainTransferFrom(
            owner, f"chain{other_chain.chain_id}", bytes(recipient), amount, b"", from_=spender
        )

        # source token manager is mint-burn

        dest_its = self.deployments[other_chain].its
        dest_token = IERC20(dest_its.validTokenAddress(token_id), chain=other_chain)
        dest_token_manager = TokenManagerProxy(dest_its.tokenManagerAddress(token_id), chain=other_chain)
        if dest_token_manager.implementationType() in {
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
            InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
        }:
            self.balances[dest_token][dest_token_manager] -= amount
        elif dest_token_manager.implementationType() == InterchainTokenService.TokenManagerType.GATEWAY:
            self.balances[dest_token][self.deployments[other_chain].gw] -= amount

        if dest_token_manager.implementationType() == InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE:
            amount -= IStatera(dest_token, chain=other_chain).cut(amount)

        self.balances[dest_token][Account(recipient, chain=other_chain)] += amount

        logger.info(f"Transferred {amount} {token.symbol()} from {chain.chain_id} to {other_chain.chain_id}")

    @flow()
    def flow_interchain_transfer(self):
        source_chain = random.choice([chain1, chain2])
        dest_chain = chain1 if source_chain == chain2 else chain2
        its = self.deployments[source_chain].its
        token_id = random.choice(self.token_ids[source_chain])
        sender = random_account(chain=source_chain)
        recipient = random_address()
        amount = random_int(0, 1_000, edge_values_prob=0.15)

        token = IERC20Named(its.validTokenAddress(token_id), chain=source_chain)
        token_manager = TokenManagerProxy(its.tokenManagerAddress(token_id), chain=source_chain)
        mint_erc20(token, sender, amount)

        if amount > 0:
            token.approve(its, amount, from_=sender)

        with may_revert((IAxelarGateway.InvalidAmount, InterchainTokenService.TakeTokenFailed)) as e:
            tx = its.interchainTransfer(
                token_id,
                "chain1" if source_chain == chain2 else "chain2",
                bytes(recipient),
                amount,
                b"",
                0,
                from_=sender,
            )

            if token_manager.implementationType() == InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE:
                amount -= IStatera(token, chain=source_chain).cut(amount)

            if token_manager.implementationType() in {
                InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
                InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
            }:
                self.balances[token][token_manager] += amount
            elif token_manager.implementationType() == InterchainTokenService.TokenManagerType.GATEWAY:
                self.balances[token][self.deployments[source_chain].gw] += amount

            dest_its = self.deployments[dest_chain].its
            dest_token = IERC20(dest_its.validTokenAddress(token_id), chain=dest_chain)
            dest_token_manager = TokenManagerProxy(dest_its.tokenManagerAddress(token_id), chain=dest_chain)
            if dest_token_manager.implementationType() in {
                InterchainTokenService.TokenManagerType.LOCK_UNLOCK,
                InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE,
            }:
                self.balances[dest_token][dest_token_manager] -= amount
            elif dest_token_manager.implementationType() == InterchainTokenService.TokenManagerType.GATEWAY:
                self.balances[dest_token][self.deployments[dest_chain].gw] -= amount

            if dest_token_manager.implementationType() == InterchainTokenService.TokenManagerType.LOCK_UNLOCK_FEE:
                amount -= IStatera(dest_token, chain=dest_chain).cut(amount)

            self.balances[dest_token][Account(recipient, chain=dest_chain)] += amount

            logger.info(f"Transferred {amount} {token.symbol()} from {source_chain.chain_id} to {dest_chain.chain_id}")

        if e.value is not None:
            assert amount == 0

    @invariant()
    def invariant_balances(self):
        for chain, d in self.deployments.items():
            for token_id in self.token_ids[chain]:
                token = IERC20Named(d.its.validTokenAddress(token_id), chain=chain)
                for a, b in self.balances[token].items():
                    assert token.balanceOf(a) == b


@chain1.connect(chain_id=1, fork="http://localhost:8545@19378463")
@chain2.connect(chain_id=2, fork="http://localhost:8545@19378463")
@on_revert(lambda e: print(e.tx.call_trace if e.tx else "Call reverted"))
def test_its_fuzz():
    ItsFuzzTest().run(10, 10_000)
