"""Exception hierarchy shared by every component of the system."""


class CredentialSharingError(Exception):
    """Base class for all errors raised by this package."""


class AuthenticationError(CredentialSharingError):
    """A party failed to authenticate (wrong password, OTP, passphrase, ...)."""


class UnauthorizedTransactionError(CredentialSharingError):
    """A ledger transaction was rejected by a smart contract."""


class DIDResolutionError(CredentialSharingError):
    """A DID could not be resolved or its DID Document is malformed."""


class CertificateValidationError(CredentialSharingError):
    """An X.509 certificate does not chain to the trust anchor or is invalid."""


class ChannelError(CredentialSharingError):
    """A message on the secure channel could not be authenticated or decrypted."""


class VerificationError(CredentialSharingError):
    """A credential or presentation failed verification."""


class WalletLockedError(CredentialSharingError):
    """An operation needed the wallet secrets while the wallet was locked."""
