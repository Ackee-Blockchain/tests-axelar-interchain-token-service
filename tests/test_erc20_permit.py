import string
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.tests.ERC20PermitMock import ERC20PermitMock


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint256
    nonce: uint256
    deadline: uint256


class Erc20PermitFuzzTest(FuzzTest):
    _erc20: ERC20PermitMock
    _name: str
    _owner: Account
    _balances: DefaultDict[Account, int]
    _allowances: DefaultDict[Account, DefaultDict[Account, int]]

    def pre_sequence(self) -> None:
        self._name = random_string(1, 10)
        self._owner = random_account()
        symbol = random_string(3, 3, alphabet=string.ascii_uppercase)
        decimals = random_int(0, 18)
        self._erc20 = ERC20PermitMock.deploy(self._name, symbol, decimals, from_=self._owner)
        assert self._erc20.name() == self._name
        assert self._erc20.symbol() == symbol
        assert self._erc20.decimals() == decimals

        self._balances = defaultdict(int)
        self._allowances = defaultdict(lambda: defaultdict(int))

    @flow()
    def flow_mint(self, amount: uint24) -> None:
        account = random_account()

        with may_revert() as e:
            self._erc20.mint(account, amount, from_=self._owner)

        if self._erc20.totalSupply() + amount >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[account] += amount

    @flow()
    def flow_permit(self) -> None:
        owner = random_account()
        spender = random_account()
        value = random_int(0, 2**256 - 1)
        expire = random_bool(true_prob=0.2)

        permit = Permit(
            owner.address, spender.address, value, self._erc20.nonces(owner), default_chain.blocks["latest"].timestamp + 100_000
        )
        signature = owner.sign_structured(permit, Eip712Domain(
            name=self._name,
            version="1",
            chainId=default_chain.chain_id,
            verifyingContract=self._erc20.address,
        ))

        if expire:
            default_chain.mine(lambda x: permit.deadline + 1)

        with may_revert() as e:
            self._erc20.permit(
                permit.owner, permit.spender, permit.value, permit.deadline, signature[64], signature[:32], signature[32:64],
                from_=random_account()
            )

        if expire:
            assert e.value == ERC20PermitMock.PermitExpired()
        else:
            assert e.value is None
            self._allowances[owner][spender] = value

    @flow()
    def flow_approve(self) -> None:
        owner = random_account()
        spender = random_account()
        value = random_int(0, 2**256 - 1)
        self._erc20.approve(spender, value, from_=owner)
        self._allowances[owner][spender] = value

    @flow()
    def flow_increase_allowance(self) -> None:
        owner = random_account()
        spender = random_account()
        value = random_int(0, 2**256 - 1)

        with may_revert() as e:
            self._erc20.increaseAllowance(spender, value, from_=owner)

        if self._allowances[owner][spender] + value >= 2 ** 256:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._allowances[owner][spender] += value

    @flow()
    def flow_decrease_allowance(self) -> None:
        owner = random_account()
        spender = random_account()
        value = random_int(0, 2**256 - 1)

        with may_revert() as e:
            self._erc20.decreaseAllowance(spender, value, from_=owner)

        if self._allowances[owner][spender] - value < 0:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._allowances[owner][spender] -= value

    @flow()
    def flow_transfer(self) -> None:
        sender = random_account()
        recipient = random_account()
        insufficient_balance = random_bool(true_prob=0.2)

        if insufficient_balance:
            amount = random_int(self._balances[sender] + 1, 2**256 - 1)
        else:
            amount = random_int(0, self._balances[sender])

        with may_revert() as e:
            self._erc20.transfer(recipient, amount, from_=sender)

        if insufficient_balance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[sender] -= amount
            self._balances[recipient] += amount

    @flow()
    def flow_transfer_from(self) -> None:
        sender = random_account()
        recipient = random_account()
        executor = random_account()
        insufficient_allowance = random_bool(true_prob=0.15)

        if insufficient_allowance:
            amount = random_int(self._allowances[sender][executor] + 1, 2**256 - 1)
            insufficient_balance = False
        else:
            amount = random_int(0, min(self._allowances[sender][executor], self._balances[sender]))
            insufficient_balance = random_bool(true_prob=0.15)

            if insufficient_balance:
                amount = random_int(self._balances[sender] + 1, 2**256 - 1)

        with may_revert() as e:
            self._erc20.transferFrom(sender, recipient, amount, from_=executor)

        if insufficient_allowance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        elif insufficient_balance:
            assert e.value == Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)
        else:
            assert e.value is None
            self._balances[sender] -= amount
            self._balances[recipient] += amount
            self._allowances[sender][executor] -= amount

    @invariant(period=10)
    def invariant_balances(self) -> None:
        for a in default_chain.accounts:
            assert self._erc20.balanceOf(a) == self._balances[a]

    @invariant(period=10)
    def invariant_allowances(self) -> None:
        for a in default_chain.accounts:
            for b in default_chain.accounts:
                assert self._erc20.allowance(a, b) == self._allowances[a][b]


@default_chain.connect()
def test_erc20_permit():
    a = default_chain.accounts[0]
    default_chain.set_default_accounts(a)

    erc20 = ERC20PermitMock.deploy("Test", "TST", 18)
    erc20.mint(a, 1000)
    assert erc20.balanceOf(a) == 1000

    with must_revert(Panic(PanicCodeEnum.UNDERFLOW_OVERFLOW)):
        erc20.mint(a, 2 ** 256 - 1)

    erc20.burn(a, 1000)
    assert erc20.totalSupply() == 0


@default_chain.connect()
def test_erc20_permit_fuzz():
    Erc20PermitFuzzTest().run(10, 1_000)
