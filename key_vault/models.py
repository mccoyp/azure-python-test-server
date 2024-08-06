from pydantic import BaseModel, Field
from typing import Union, Literal, Optional, List
from key_vault import KeyAttributes, KeyReleasePolicy, JsonWebKey, Error, KeyItem, DeletedKeyItem, LifetimeActions, LifetimeActionsTrigger, LifetimeActionsType, KeyRotationPolicyAttributes
from enum import Enum

class KeyAttributes(BaseModel):
    """The attributes of a key managed by the key vault service."""
    enabled: Optional[bool] = Field(description="Determines whether the object is enabled.", default=None)
    """Determines whether the object is enabled."""

    not_before: Optional[datetime] = Field(description="Not before date in UTC.", default=None)
    """Not before date in UTC."""

    expires: Optional[datetime] = Field(description="Expiry date in UTC.", default=None)
    """Expiry date in UTC."""

    created: Optional[datetime] = Field(description="Creation time in UTC.", default=None, frozen=True)
    """Creation time in UTC."""

    updated: Optional[datetime] = Field(description="Last updated time in UTC.", default=None, frozen=True)
    """Last updated time in UTC."""

    recoverable_days: Optional[int] = Field(description="softDelete data retention days. Value should be >=7 and <=90 when softDelete\nenabled, otherwise 0.", default=None, frozen=True)
    """
    softDelete data retention days. Value should be >=7 and <=90 when softDelete
    enabled, otherwise 0.
    """

    recovery_level: Optional[Union[Literal["Purgeable", "Recoverable+Purgeable", "Recoverable", "Recoverable+ProtectedSubscription", "CustomizedRecoverable+Purgeable", "CustomizedRecoverable", "CustomizedRecoverable+ProtectedSubscription"], str]] = Field(description="Reflects the deletion recovery level currently in effect for keys in the\ncurrent vault. If it contains 'Purgeable' the key can be permanently deleted by\na privileged user; otherwise, only the system can purge the key, at the end of\nthe retention interval.", default=None, frozen=True)
    """
    Reflects the deletion recovery level currently in effect for keys in the
    current vault. If it contains 'Purgeable' the key can be permanently deleted by
    a privileged user; otherwise, only the system can purge the key, at the end of
    the retention interval.
    """

    exportable: Optional[bool] = Field(description="Indicates if the private key can be exported. Release policy must be provided\nwhen creating the first version of an exportable key.", default=None)
    """
    Indicates if the private key can be exported. Release policy must be provided
    when creating the first version of an exportable key.
    """

    hsm_platform: Optional[str] = Field(description="The underlying HSM Platform.", default=None, frozen=True)
    """The underlying HSM Platform."""


class KeyReleasePolicy(BaseModel):
    """The policy rules under which the key can be exported."""
    content_type: Optional[str] = Field(description="Content type and version of key release policy", default="application/json; charset=utf-8")
    """Content type and version of key release policy"""

    immutable: Optional[bool] = Field(description="Defines the mutability state of the policy. Once marked immutable, this flag\ncannot be reset and the policy cannot be changed under any circumstances.", default=None)
    """
    Defines the mutability state of the policy. Once marked immutable, this flag
    cannot be reset and the policy cannot be changed under any circumstances.
    """

    encoded_policy: Optional[bytes] = Field(description="Blob encoding the policy rules under which the key can be released. Blob must\nbe base64 URL encoded.", default=None)
    """
    Blob encoding the policy rules under which the key can be released. Blob must
    be base64 URL encoded.
    """


class KeyCreateParameters(BaseModel):
    """The key create parameters."""
    kty: Union[Literal["EC", "EC-HSM", "RSA", "RSA-HSM", "oct", "oct-HSM"], str] = Field(description="The type of key to create. For valid values, see JsonWebKeyType.")
    """The type of key to create. For valid values, see JsonWebKeyType."""

    key_size: Optional[int] = Field(description="The key size in bits. For example: 2048, 3072, or 4096 for RSA.", default=None)
    """The key size in bits. For example: 2048, 3072, or 4096 for RSA."""

    public_exponent: Optional[int] = Field(description="The public exponent for a RSA key.", default=None)
    """The public exponent for a RSA key."""

    key_ops: Optional[List[JsonWebKeyOperation]] = Field(default=None)

    key_attributes: Optional[KeyAttributes] = Field(description="The attributes of a key managed by the key vault service.", default=None)
    """The attributes of a key managed by the key vault service."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    curve: Optional[Union[Literal["P-256", "P-384", "P-521", "P-256K"], str]] = Field(description="Elliptic curve name. For valid values, see JsonWebKeyCurveName.", default=None)
    """Elliptic curve name. For valid values, see JsonWebKeyCurveName."""

    release_policy: Optional[KeyReleasePolicy] = Field(description="The policy rules under which the key can be exported.", default=None)
    """The policy rules under which the key can be exported."""


class Attributes(BaseModel):
    """The object attributes managed by the KeyVault service."""
    enabled: Optional[bool] = Field(description="Determines whether the object is enabled.", default=None)
    """Determines whether the object is enabled."""

    not_before: Optional[datetime] = Field(description="Not before date in UTC.", default=None)
    """Not before date in UTC."""

    expires: Optional[datetime] = Field(description="Expiry date in UTC.", default=None)
    """Expiry date in UTC."""

    created: Optional[datetime] = Field(description="Creation time in UTC.", default=None, frozen=True)
    """Creation time in UTC."""

    updated: Optional[datetime] = Field(description="Last updated time in UTC.", default=None, frozen=True)
    """Last updated time in UTC."""


class JsonWebKey(BaseModel):
    """As of http://tools.ietf.org/html/draft-ietf-jose-json-web-key-18"""
    kid: Optional[str] = Field(description="Key identifier.", default=None)
    """Key identifier."""

    kty: Optional[Union[Literal["EC", "EC-HSM", "RSA", "RSA-HSM", "oct", "oct-HSM"], str]] = Field(description="JsonWebKey Key Type (kty), as defined in\nhttps://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40.", default=None)
    """
    JsonWebKey Key Type (kty), as defined in
    https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40.
    """

    key_ops: Optional[List[str]] = Field(default=None)

    n: Optional[bytes] = Field(description="RSA modulus.", default=None)
    """RSA modulus."""

    e: Optional[bytes] = Field(description="RSA public exponent.", default=None)
    """RSA public exponent."""

    d: Optional[bytes] = Field(description="RSA private exponent, or the D component of an EC private key.", default=None)
    """RSA private exponent, or the D component of an EC private key."""

    dp: Optional[bytes] = Field(description="RSA private key parameter.", default=None)
    """RSA private key parameter."""

    dq: Optional[bytes] = Field(description="RSA private key parameter.", default=None)
    """RSA private key parameter."""

    qi: Optional[bytes] = Field(description="RSA private key parameter.", default=None)
    """RSA private key parameter."""

    p: Optional[bytes] = Field(description="RSA secret prime.", default=None)
    """RSA secret prime."""

    q: Optional[bytes] = Field(description="RSA secret prime, with p < q.", default=None)
    """RSA secret prime, with p < q."""

    k: Optional[bytes] = Field(description="Symmetric key.", default=None)
    """Symmetric key."""

    t: Optional[bytes] = Field(description="Protected Key, used with 'Bring Your Own Key'.", default=None)
    """Protected Key, used with 'Bring Your Own Key'."""

    crv: Optional[Union[Literal["P-256", "P-384", "P-521", "P-256K"], str]] = Field(description="Elliptic curve name. For valid values, see JsonWebKeyCurveName.", default=None)
    """Elliptic curve name. For valid values, see JsonWebKeyCurveName."""

    x: Optional[bytes] = Field(description="X component of an EC public key.", default=None)
    """X component of an EC public key."""

    y: Optional[bytes] = Field(description="Y component of an EC public key.", default=None)
    """Y component of an EC public key."""


class KeyBundle(BaseModel):
    """A KeyBundle consisting of a WebKey plus its attributes."""
    key: Optional[JsonWebKey] = Field(description="The Json web key.", default=None)
    """The Json web key."""

    attributes: Optional[KeyAttributes] = Field(description="The key management attributes.", default=None)
    """The key management attributes."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    managed: Optional[bool] = Field(description="True if the key's lifetime is managed by key vault. If this is a key backing a\ncertificate, then managed will be true.", default=None, frozen=True)
    """
    True if the key's lifetime is managed by key vault. If this is a key backing a
    certificate, then managed will be true.
    """

    release_policy: Optional[KeyReleasePolicy] = Field(description="The policy rules under which the key can be exported.", default=None)
    """The policy rules under which the key can be exported."""


class Error(BaseModel):
    """The key vault server error."""
    code: Optional[str] = Field(description="The error code.", default=None, frozen=True)
    """The error code."""

    message: Optional[str] = Field(description="The error message.", default=None, frozen=True)
    """The error message."""

    inner_error: Optional["Error"] = Field(description="The key vault server error.", default=None, frozen=True)
    """The key vault server error."""


class KeyVaultError(BaseModel):
    """The key vault error exception."""
    error: Optional[Error] = Field(description="The key vault server error.", default=None, frozen=True)
    """The key vault server error."""


class KeyImportParameters(BaseModel):
    """The key import parameters."""
    hsm: Optional[bool] = Field(description="Whether to import as a hardware key (HSM) or software key.", default=None)
    """Whether to import as a hardware key (HSM) or software key."""

    key: JsonWebKey = Field(description="The Json web key")
    """The Json web key"""

    key_attributes: Optional[KeyAttributes] = Field(description="The key management attributes.", default=None)
    """The key management attributes."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    release_policy: Optional[KeyReleasePolicy] = Field(description="The policy rules under which the key can be exported.", default=None)
    """The policy rules under which the key can be exported."""


class DeletedKeyBundle(BaseModel):
    """A DeletedKeyBundle consisting of a WebKey plus its Attributes and deletion info"""
    key: Optional[JsonWebKey] = Field(description="The Json web key.", default=None)
    """The Json web key."""

    attributes: Optional[KeyAttributes] = Field(description="The key management attributes.", default=None)
    """The key management attributes."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    managed: Optional[bool] = Field(description="True if the key's lifetime is managed by key vault. If this is a key backing a\ncertificate, then managed will be true.", default=None, frozen=True)
    """
    True if the key's lifetime is managed by key vault. If this is a key backing a
    certificate, then managed will be true.
    """

    release_policy: Optional[KeyReleasePolicy] = Field(description="The policy rules under which the key can be exported.", default=None)
    """The policy rules under which the key can be exported."""

    recovery_id: Optional[str] = Field(description="The url of the recovery object, used to identify and recover the deleted key.", default=None)
    """The url of the recovery object, used to identify and recover the deleted key."""

    scheduled_purge_date: Optional[datetime] = Field(description="The time when the key is scheduled to be purged, in UTC", default=None, frozen=True)
    """The time when the key is scheduled to be purged, in UTC"""

    deleted_date: Optional[datetime] = Field(description="The time when the key was deleted, in UTC", default=None, frozen=True)
    """The time when the key was deleted, in UTC"""


class KeyUpdateParameters(BaseModel):
    """The key update parameters."""
    key_ops: Optional[List[JsonWebKeyOperation]] = Field(description="Json web key operations. For more information on possible key operations, see\nJsonWebKeyOperation.", default=None)
    """
    Json web key operations. For more information on possible key operations, see
    JsonWebKeyOperation.
    """

    key_attributes: Optional[KeyAttributes] = Field(description="The attributes of a key managed by the key vault service.", default=None)
    """The attributes of a key managed by the key vault service."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    release_policy: Optional[KeyReleasePolicy] = Field(description="The policy rules under which the key can be exported.", default=None)
    """The policy rules under which the key can be exported."""


class KeyItem(BaseModel):
    """The key item containing key metadata."""
    kid: str = Field(description="Key identifier.")
    """Key identifier."""

    attributes: Optional[KeyAttributes] = Field(description="The key management attributes.", default=None)
    """The key management attributes."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    managed: Optional[bool] = Field(description="True if the key's lifetime is managed by key vault. If this is a key backing a\ncertificate, then managed will be true.", default=None, frozen=True)
    """
    True if the key's lifetime is managed by key vault. If this is a key backing a
    certificate, then managed will be true.
    """


class KeyListResult(BaseModel):
    """The key list result."""
    value: List[KeyItem] = Field(description="The KeyItem items on this page")
    """The KeyItem items on this page"""

    next_link: Optional[ResourceLocationKeyItem] = Field(description="The link to the next page of items", default=None)
    """The link to the next page of items"""


class BackupKeyResult(BaseModel):
    """The backup key result, containing the backup blob."""
    value: Optional[bytes] = Field(description="The backup blob containing the backed up key.", default=None, frozen=True)
    """The backup blob containing the backed up key."""


class KeyRestoreParameters(BaseModel):
    """The key restore parameters."""
    key_bundle_backup: bytes = Field(description="The backup blob associated with a key bundle.")
    """The backup blob associated with a key bundle."""


class KeyOperationsParameters(BaseModel):
    """The key operations parameters."""
    algorithm: Union[Literal["RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "A128GCM", "A192GCM", "A256GCM", "A128KW", "A192KW", "A256KW", "A128CBC", "A192CBC", "A256CBC", "A128CBCPAD", "A192CBCPAD", "A256CBCPAD"], str] = Field(description="algorithm identifier")
    """algorithm identifier"""

    value: bytes

    iv: Optional[bytes] = Field(description="Cryptographically random, non-repeating initialization vector for symmetric\nalgorithms.", default=None)
    """
    Cryptographically random, non-repeating initialization vector for symmetric
    algorithms.
    """

    aad: Optional[bytes] = Field(description="Additional data to authenticate but not encrypt/decrypt when using\nauthenticated crypto algorithms.", default=None)
    """
    Additional data to authenticate but not encrypt/decrypt when using
    authenticated crypto algorithms.
    """

    tag: Optional[bytes] = Field(description="The tag to authenticate when performing decryption with an authenticated\nalgorithm.", default=None)
    """
    The tag to authenticate when performing decryption with an authenticated
    algorithm.
    """


class KeyOperationResult(BaseModel):
    """The key operation result."""
    kid: Optional[str] = Field(description="Key identifier", default=None, frozen=True)
    """Key identifier"""

    result: Optional[bytes] = Field(default=None, frozen=True)

    iv: Optional[bytes] = Field(default=None, frozen=True)

    authentication_tag: Optional[bytes] = Field(default=None, frozen=True)

    additional_authenticated_data: Optional[bytes] = Field(default=None, frozen=True)


class KeySignParameters(BaseModel):
    """The key operations parameters."""
    algorithm: Union[Literal["PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RSNULL", "ES256", "ES384", "ES512", "ES256K"], str] = Field(description="The signing/verification algorithm identifier. For more information on possible\nalgorithm types, see JsonWebKeySignatureAlgorithm.")
    """
    The signing/verification algorithm identifier. For more information on possible
    algorithm types, see JsonWebKeySignatureAlgorithm.
    """

    value: bytes


class KeyVerifyParameters(BaseModel):
    """The key verify parameters."""
    algorithm: Union[Literal["PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RSNULL", "ES256", "ES384", "ES512", "ES256K"], str] = Field(description="The signing/verification algorithm. For more information on possible algorithm\ntypes, see JsonWebKeySignatureAlgorithm.")
    """
    The signing/verification algorithm. For more information on possible algorithm
    types, see JsonWebKeySignatureAlgorithm.
    """

    digest: bytes = Field(description="The digest used for signing.")
    """The digest used for signing."""

    signature: bytes = Field(description="The signature to be verified.")
    """The signature to be verified."""


class KeyVerifyResult(BaseModel):
    """The key verify result."""
    value: Optional[bool] = Field(description="True if the signature is verified, otherwise false.", default=None, frozen=True)
    """True if the signature is verified, otherwise false."""


class KeyReleaseParameters(BaseModel):
    """The release key parameters."""
    target_attestation_token: str = Field(description="The attestation assertion for the target of the key release.", min_length=1)
    """The attestation assertion for the target of the key release."""

    nonce: Optional[str] = Field(description="A client provided nonce for freshness.", default=None)
    """A client provided nonce for freshness."""

    enc: Optional[Union[Literal["CKM_RSA_AES_KEY_WRAP", "RSA_AES_KEY_WRAP_256", "RSA_AES_KEY_WRAP_384"], str]] = Field(description="The encryption algorithm to use to protected the exported key material", default=None)
    """The encryption algorithm to use to protected the exported key material"""


class KeyReleaseResult(BaseModel):
    """The release result, containing the released key."""
    value: Optional[str] = Field(description="A signed object containing the released key.", default=None, frozen=True)
    """A signed object containing the released key."""


class DeletedKeyItem(BaseModel):
    """
    The deleted key item containing the deleted key metadata and information about
    deletion.
    """
    kid: str = Field(description="Key identifier.")
    """Key identifier."""

    attributes: Optional[KeyAttributes] = Field(description="The key management attributes.", default=None)
    """The key management attributes."""

    tags: Optional[Dict[str, str]] = Field(description="Application specific metadata in the form of key-value pairs.", default=None)
    """Application specific metadata in the form of key-value pairs."""

    managed: Optional[bool] = Field(description="True if the key's lifetime is managed by key vault. If this is a key backing a\ncertificate, then managed will be true.", default=None, frozen=True)
    """
    True if the key's lifetime is managed by key vault. If this is a key backing a
    certificate, then managed will be true.
    """

    recovery_id: Optional[str] = Field(description="The url of the recovery object, used to identify and recover the deleted key.", default=None)
    """The url of the recovery object, used to identify and recover the deleted key."""

    scheduled_purge_date: Optional[datetime] = Field(description="The time when the key is scheduled to be purged, in UTC", default=None, frozen=True)
    """The time when the key is scheduled to be purged, in UTC"""

    deleted_date: Optional[datetime] = Field(description="The time when the key was deleted, in UTC", default=None, frozen=True)
    """The time when the key was deleted, in UTC"""


class DeletedKeyListResult(BaseModel):
    """A list of keys that have been deleted in this vault."""
    value: List[DeletedKeyItem] = Field(description="The DeletedKeyItem items on this page")
    """The DeletedKeyItem items on this page"""

    next_link: Optional[ResourceLocationDeletedKeyItem] = Field(description="The link to the next page of items", default=None)
    """The link to the next page of items"""


class LifetimeActionsTrigger(BaseModel):
    """A condition to be satisfied for an action to be executed."""
    time_after_create: Optional[str] = Field(description="Time after creation to attempt to rotate. It only applies to rotate. It will be\nin ISO 8601 duration format. Example: 90 days : "P90D"", default=None)
    """
    Time after creation to attempt to rotate. It only applies to rotate. It will be
    in ISO 8601 duration format. Example: 90 days : "P90D"
    """

    time_before_expiry: Optional[str] = Field(description="Time before expiry to attempt to rotate or notify. It will be in ISO 8601\nduration format. Example: 90 days : "P90D"", default=None)
    """
    Time before expiry to attempt to rotate or notify. It will be in ISO 8601
    duration format. Example: 90 days : "P90D"
    """


class LifetimeActionsType(BaseModel):
    """The action that will be executed."""
    type: Optional[Union[Literal["Rotate", "Notify"], str]] = Field(description="The type of the action. The value should be compared case-insensitively.", default=None)
    """The type of the action. The value should be compared case-insensitively."""


class LifetimeActions(BaseModel):
    """
    Action and its trigger that will be performed by Key Vault over the lifetime of
    a key.
    """
    trigger: Optional[LifetimeActionsTrigger] = Field(description="The condition that will execute the action.", default=None)
    """The condition that will execute the action."""

    action: Optional[LifetimeActionsType] = Field(description="The action that will be executed.", default=None)
    """The action that will be executed."""


class KeyRotationPolicyAttributes(BaseModel):
    """The key rotation policy attributes."""
    expiry_time: Optional[str] = Field(description="The expiryTime will be applied on the new key version. It should be at least 28\ndays. It will be in ISO 8601 Format. Examples: 90 days: P90D, 3 months: P3M, 48\nhours: PT48H, 1 year and 10 days: P1Y10D", default=None)
    """
    The expiryTime will be applied on the new key version. It should be at least 28
    days. It will be in ISO 8601 Format. Examples: 90 days: P90D, 3 months: P3M, 48
    hours: PT48H, 1 year and 10 days: P1Y10D
    """

    created: Optional[datetime] = Field(description="The key rotation policy created time in UTC.", default=None, frozen=True)
    """The key rotation policy created time in UTC."""

    updated: Optional[datetime] = Field(description="The key rotation policy's last updated time in UTC.", default=None, frozen=True)
    """The key rotation policy's last updated time in UTC."""


class KeyRotationPolicy(BaseModel):
    """Management policy for a key."""
    id: Optional[str] = Field(description="The key policy id.", default=None, frozen=True)
    """The key policy id."""

    lifetime_actions: Optional[List[LifetimeActions]] = Field(description="Actions that will be performed by Key Vault over the lifetime of a key. For\npreview, lifetimeActions can only have two items at maximum: one for rotate,\none for notify. Notification time would be default to 30 days before expiry and\nit is not configurable.", default=None)
    """
    Actions that will be performed by Key Vault over the lifetime of a key. For
    preview, lifetimeActions can only have two items at maximum: one for rotate,
    one for notify. Notification time would be default to 30 days before expiry and
    it is not configurable.
    """

    attributes: Optional[KeyRotationPolicyAttributes] = Field(description="The key rotation policy attributes.", default=None)
    """The key rotation policy attributes."""


class GetRandomBytesRequest(BaseModel):
    """The get random bytes request object."""
    count: int = Field(description="The requested number of random bytes.", ge=1, le=128)
    """The requested number of random bytes."""


class RandomBytes(BaseModel):
    """The get random bytes response object containing the bytes."""
    value: bytes = Field(description="The bytes encoded as a base64url string.")
    """The bytes encoded as a base64url string."""


class KeyProperties(BaseModel):
    """Properties of the key pair backing a certificate."""
    exportable: Optional[bool] = Field(description="Indicates if the private key can be exported. Release policy must be provided\nwhen creating the first version of an exportable key.", default=None)
    """
    Indicates if the private key can be exported. Release policy must be provided
    when creating the first version of an exportable key.
    """

    key_type: Optional[Union[Literal["EC", "EC-HSM", "RSA", "RSA-HSM", "oct", "oct-HSM"], str]] = Field(description="The type of key pair to be used for the certificate.", default=None, min_length=1)
    """The type of key pair to be used for the certificate."""

    key_size: Optional[int] = Field(description="The key size in bits. For example: 2048, 3072, or 4096 for RSA.", default=None)
    """The key size in bits. For example: 2048, 3072, or 4096 for RSA."""

    reuse_key: Optional[bool] = Field(description="Indicates if the same key pair will be used on certificate renewal.", default=None)
    """Indicates if the same key pair will be used on certificate renewal."""

    curve: Optional[Union[Literal["P-256", "P-384", "P-521", "P-256K"], str]] = Field(description="Elliptic curve name. For valid values, see JsonWebKeyCurveName.", default=None)
    """Elliptic curve name. For valid values, see JsonWebKeyCurveName."""


class KeyExportParameters(BaseModel):
    """The export key parameters."""
    wrapping_key: Optional[JsonWebKey] = Field(description="The export key encryption Json web key. This key MUST be a RSA key that\nsupports encryption.", default=None)
    """
    The export key encryption Json web key. This key MUST be a RSA key that
    supports encryption.
    """

    wrapping_kid: Optional[str] = Field(description="The export key encryption key identifier. This key MUST be a RSA key that\nsupports encryption.", default=None)
    """
    The export key encryption key identifier. This key MUST be a RSA key that
    supports encryption.
    """

    enc: Optional[Union[Literal["CKM_RSA_AES_KEY_WRAP", "RSA_AES_KEY_WRAP_256", "RSA_AES_KEY_WRAP_384"], str]] = Field(description="The encryption algorithm to use to protected the exported key material", default=None)
    """The encryption algorithm to use to protected the exported key material"""


class Versions(Enum):
    """The available API versions."""
    V7.6_PREVIEW.1 = Field(description="The 7.6-preview.1 API version.", default="7.6-preview.1", frozen=True)
    """The 7.6-preview.1 API version."""
