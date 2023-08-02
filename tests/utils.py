from woke.testing import *
from pytypes.axelarnetwork.axelarcgpsolidity.contracts.TokenDeployer import TokenDeployer
from pytypes.axelarnetwork.axelarcgpsolidity.contracts.gasservice.AxelarGasService import AxelarGasService

from pytypes.axelarnetwork.axelargmpsdksolidity.contracts.deploy.Create3Deployer import Create3Deployer
from pytypes.source.contracts.interchainTokenService.InterchainTokenService import InterchainTokenService
from pytypes.source.contracts.linkerRouter.LinkerRouter import LinkerRouter
from pytypes.source.contracts.proxies.InterchainTokenServiceProxy import InterchainTokenServiceProxy
from pytypes.source.contracts.proxies.LinkerRouterProxy import LinkerRouterProxy
from pytypes.source.contracts.proxies.TokenManagerProxy import TokenManagerProxy
from pytypes.source.contracts.tokenManager.implementations.TokenManagerLiquidityPool import TokenManagerLiquidityPool
from pytypes.source.contracts.tokenManager.implementations.TokenManagerLockUnlock import TokenManagerLockUnlock
from pytypes.source.contracts.tokenManager.implementations.TokenManagerMintBurn import TokenManagerMintBurn
from pytypes.source.contracts.utils.BytecodeServer import BytecodeServer
from pytypes.source.contracts.utils.MockAxelarGateway import MockAxelarGateway
from pytypes.tests.TokenManagerCanonicalMock import TokenManagerCanonicalMock


def deploy_interchain_token_service(chain: Chain, owner: Account):
    deployer = Create3Deployer.deploy(chain=chain)
    token_deployer = TokenDeployer.deploy(chain=chain)
    gateway = MockAxelarGateway.deploy(token_deployer, chain=chain)
    gas_service = AxelarGasService.deploy(chain=chain)

    bytecode_server = BytecodeServer.deploy(TokenManagerProxy.get_creation_code(), chain=chain)
    service_proxy_addr = deployer.deployedAddress(owner, keccak256(b'service'))

    linker_router_impl = LinkerRouter.deploy(service_proxy_addr, [], [], chain=chain)
    linker_router = LinkerRouterProxy.deploy(linker_router_impl, owner, chain=chain)

    mgr_lock_unlock = TokenManagerLockUnlock.deploy(service_proxy_addr, chain=chain)
    mgr_mint_burn = TokenManagerMintBurn.deploy(service_proxy_addr, chain=chain)
    mgr_canonical = TokenManagerCanonicalMock.deploy(service_proxy_addr, chain=chain)
    mgr_liquidity_pool = TokenManagerLiquidityPool.deploy(service_proxy_addr, chain=chain)

    token_service_impl = InterchainTokenService.deploy(
        deployer,
        bytecode_server,
        gateway,
        gas_service,
        linker_router,
        [mgr_lock_unlock.address, mgr_mint_burn.address, mgr_canonical.address, mgr_liquidity_pool.address],
        "test",
        chain=chain,
    )
    tx = deployer.deploy_(
        InterchainTokenServiceProxy.get_creation_code()
        + Abi.encode(["address","address","bytes"], [token_service_impl.address, owner, b'']),
        keccak256(b'service')
    )
    assert tx.return_value == service_proxy_addr
    return InterchainTokenService(service_proxy_addr, chain=chain), gateway
