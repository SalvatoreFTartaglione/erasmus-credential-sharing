"""Student authentication at the issuer portal: password + one-time password.

* Passwords are stored as salted scrypt hashes (RFC 7914) and compared in
  constant time.
* OTPs come from :mod:`secrets`, expire after a short time and are single use.
* A per-account :class:`Throttle` applies exponential back-off after each
  failure and locks the account after too many failures (brute-force defence
  described in WP2, phase 2).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from credential_sharing.encoding import b64url_decode, b64url_encode
from credential_sharing.errors import AuthenticationError

Clock = Callable[[], float]


class PasswordHasher:
    N, R, P, KEY_LENGTH = 2**14, 8, 1, 32

    @classmethod
    def hash(cls, password: str) -> str:
        salt = secrets.token_bytes(16)
        key = hashlib.scrypt(password.encode(), salt=salt, n=cls.N, r=cls.R, p=cls.P, dklen=cls.KEY_LENGTH)
        return f"scrypt${cls.N}${cls.R}${cls.P}${b64url_encode(salt)}${b64url_encode(key)}"

    @staticmethod
    def verify(password: str, encoded: str) -> bool:
        try:
            scheme, n, r, p, salt, expected = encoded.split("$")
            if scheme != "scrypt":
                return False
            key = hashlib.scrypt(
                password.encode(), salt=b64url_decode(salt), n=int(n), r=int(r), p=int(p),
                dklen=len(b64url_decode(expected)),
            )
        except ValueError:
            return False
        return hmac.compare_digest(key, b64url_decode(expected))


@dataclass
class _ThrottleState:
    failures: int = 0
    blocked_until: float = 0.0


class Throttle:
    """Exponential back-off (1s, 2s, 4s, ...) and lock-out after ``max_failures``."""

    def __init__(self, max_failures: int = 5, base_delay: float = 1.0, clock: Clock = time.monotonic) -> None:
        self._max_failures = max_failures
        self._base_delay = base_delay
        self._clock = clock
        self._state: dict[str, _ThrottleState] = {}

    def check(self, account: str) -> None:
        state = self._state.get(account)
        if state is None:
            return
        if state.failures >= self._max_failures:
            raise AuthenticationError("account locked after too many failed attempts")
        wait = state.blocked_until - self._clock()
        if wait > 0:
            raise AuthenticationError(f"too many attempts: retry in {wait:.0f} s")

    def retry_after(self, account: str) -> float:
        state = self._state.get(account)
        return max(0.0, state.blocked_until - self._clock()) if state else 0.0

    def failure(self, account: str) -> None:
        state = self._state.setdefault(account, _ThrottleState())
        state.failures += 1
        state.blocked_until = self._clock() + self._base_delay * 2 ** (state.failures - 1)

    def success(self, account: str) -> None:
        self._state.pop(account, None)


@dataclass
class _PendingOtp:
    digest: bytes
    expires_at: float


class OtpService:
    """Six-digit, single-use, short-lived one-time passwords."""

    def __init__(self, deliver: Callable[[str, str], None], ttl_seconds: float = 120.0,
                 clock: Clock = time.monotonic) -> None:
        self._deliver = deliver
        self._ttl = ttl_seconds
        self._clock = clock
        self._pending: dict[str, _PendingOtp] = {}

    @staticmethod
    def _digest(code: str) -> bytes:
        return hashlib.sha256(code.encode()).digest()

    def issue(self, account: str, address: str) -> None:
        code = f"{secrets.randbelow(10**6):06d}"
        self._pending[account] = _PendingOtp(self._digest(code), self._clock() + self._ttl)
        self._deliver(address, code)

    def verify(self, account: str, code: str) -> bool:
        pending = self._pending.get(account)
        if pending is None:
            return False
        if self._clock() > pending.expires_at:
            del self._pending[account]
            return False
        if hmac.compare_digest(pending.digest, self._digest(code)):
            del self._pending[account]  # single use
            return True
        return False


@dataclass
class SimulatedMailbox:
    """Stands in for the e-mail/SMS gateway that delivers OTPs."""

    messages: list[tuple[str, str]] = field(default_factory=list)

    def deliver(self, address: str, code: str) -> None:
        self.messages.append((address, code))

    def last_code(self, address: str) -> str:
        for recipient, code in reversed(self.messages):
            if recipient == address:
                return code
        raise LookupError(f"no message for {address}")
