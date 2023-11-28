from wake.testing import *

from pytypes.tests.FlowLimitMock import FlowLimitMock


@default_chain.connect()
def test_flow_limit():
    a = default_chain.accounts[0]
    default_chain.set_default_accounts(a)

    mock = FlowLimitMock.deploy()
    assert mock.getFlowLimit() == 0
    assert mock.getFlowOutAmount() == 0
    assert mock.getFlowInAmount() == 0

    mock.setFlowLimit(100)
    assert mock.getFlowLimit() == 100
    assert mock.getFlowOutAmount() == 0
    assert mock.getFlowInAmount() == 0

    mock.addFlowIn(100)
    assert mock.getFlowLimit() == 100
    assert mock.getFlowOutAmount() == 0
    assert mock.getFlowInAmount() == 100

    with must_revert(mock.FlowLimitExceeded()):
        mock.addFlowIn(1)

    mock.addFlowOut(100)
    assert mock.getFlowLimit() == 100
    assert mock.getFlowOutAmount() == 100
    assert mock.getFlowInAmount() == 100

    mock.addFlowOut(100)
    assert mock.getFlowLimit() == 100
    assert mock.getFlowOutAmount() == 200
    assert mock.getFlowInAmount() == 100

    with must_revert(mock.FlowLimitExceeded()):
        mock.addFlowOut(1)

    default_chain.mine(lambda x: x + 6 * 60 * 60)
    assert mock.getFlowLimit() == 100
    assert mock.getFlowOutAmount() == 0
    assert mock.getFlowInAmount() == 0
