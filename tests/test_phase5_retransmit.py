# tests/test_phase5_retransmit.py
from tunneltwin.capture.retransmit import opens_negotiation

ZERO = b"\x00" * 8
A = b"\x11" * 8
B = b"\x22" * 8


def test_sa_init_from_initiator_opens_negotiation():
    assert opens_negotiation(A, ZERO) is True


def test_sa_init_reply_does_not_open_negotiation():
    # responder's reply: initiator SPI echoed, responder SPI chosen
    assert opens_negotiation(A, B) is False


def test_all_zero_is_not_a_negotiation_open():
    # malformed / non-IKE payload; must not be counted
    assert opens_negotiation(ZERO, ZERO) is False


def test_subsequent_packet_does_not_open_negotiation():
    # e.g. IKE_AUTH, INFORMATIONAL, rekey -- both SPIs already set
    assert opens_negotiation(A, B) is False
