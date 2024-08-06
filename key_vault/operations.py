from key_vault import KeyCreateParameters, KeyBundle, KeyImportParameters, DeletedKeyBundle, KeyUpdateParameters, KeyListResult, BackupKeyResult, KeyRestoreParameters, KeyOperationsParameters, KeyOperationResult, KeySignParameters, KeyVerifyParameters, KeyVerifyResult, KeyReleaseParameters, KeyReleaseResult, KeyRotationPolicy, GetRandomBytesRequest, RandomBytes
from azure.core.foundations import ErrorResponse
from typing import Union, Literal
from key_vault._operations import _create_key, _rotate_key, _import_key, _delete_key, _update_key, _get_key, _get_key_versions, _get_keys, _backup_key, _restore_key, _encrypt, _decrypt, _sign, _verify, _wrap_key, _unwrap_key, _release, _get_deleted_keys, _get_deleted_key, _purge_deleted_key, _recover_deleted_key, _get_key_rotation_policy, _update_key_rotation_policy, _get_random_bytes
from flask import Flask

app = Flask(__name__)

    """
    The create key operation can be used to create any key type in Azure Key Vault.
    If the named key already exists, Azure Key Vault creates a new version of the
    key. It requires the keys/create permission.
    """
@app.route("/keys/<keyName>/create", methods=["POST"])
def create_key(api_version: str, key_name: str, parameters: KeyCreateParameters) -> Union[KeyBundle, ErrorResponse]:
    return _create_key(api_version, key_name, parameters)

    """
    The operation will rotate the key based on the key policy. It requires the
    keys/rotate permission.
    """
@app.route("/keys/<keyName>/rotate", methods=["POST"])
def rotate_key(api_version: str, key_name: str) -> Union[KeyBundle, ErrorResponse]:
    return _rotate_key(api_version, key_name)

    """
    The import key operation may be used to import any key type into an Azure Key
    Vault. If the named key already exists, Azure Key Vault creates a new version
    of the key. This operation requires the keys/import permission.
    """
@app.route("/keys/<keyName>", methods=["PUT"])
def import_key(api_version: str, key_name: str, parameters: KeyImportParameters) -> Union[KeyBundle, ErrorResponse]:
    return _import_key(api_version, key_name, parameters)

    """
    The delete key operation cannot be used to remove individual versions of a key.
    This operation removes the cryptographic material associated with the key,
    which means the key is not usable for Sign/Verify, Wrap/Unwrap or
    Encrypt/Decrypt operations. This operation requires the keys/delete permission.
    """
@app.route("/keys/<keyName>", methods=["DELETE"])
def delete_key(api_version: str, key_name: str) -> Union[DeletedKeyBundle, ErrorResponse]:
    return _delete_key(api_version, key_name)

    """
    In order to perform this operation, the key must already exist in the Key
    Vault. Note: The cryptographic material of a key itself cannot be changed. This
    operation requires the keys/update permission.
    """
@app.route("/keys/<keyName>/<keyVersion>", methods=["PATCH"])
def update_key(api_version: str, key_name: str, key_version: str, parameters: KeyUpdateParameters) -> Union[KeyBundle, ErrorResponse]:
    return _update_key(api_version, key_name, key_version, parameters)

    """
    The get key operation is applicable to all key types. If the requested key is
    symmetric, then no key material is released in the response. This operation
    requires the keys/get permission.
    """
@app.route("/keys/<keyName>/<keyVersion>", methods=["GET"])
def get_key(api_version: str, key_name: str, key_version: str) -> Union[KeyBundle, ErrorResponse]:
    return _get_key(api_version, key_name, key_version)

    """
    The full key identifier, attributes, and tags are provided in the response.
    This operation requires the keys/list permission.
    """
@app.route("/keys/<keyName>/versions", methods=["GET"])
def get_key_versions(api_version: str, key_name: str, maxresults: int) -> Union[KeyListResult, ErrorResponse]:
    return _get_key_versions(api_version, key_name, maxresults)

    """
    Retrieves a list of the keys in the Key Vault as JSON Web Key structures that
    contain the public part of a stored key. The LIST operation is applicable to
    all key types, however only the base key identifier, attributes, and tags are
    provided in the response. Individual versions of a key are not listed in the
    response. This operation requires the keys/list permission.
    """
@app.route("/keys", methods=["GET"])
def get_keys(api_version: str, maxresults: int) -> Union[, ErrorResponse]:
    return _get_keys(api_version, maxresults)

    """
    The Key Backup operation exports a key from Azure Key Vault in a protected
    form. Note that this operation does NOT return key material in a form that can
    be used outside the Azure Key Vault system, the returned key material is either
    protected to a Azure Key Vault HSM or to Azure Key Vault itself. The intent of
    this operation is to allow a client to GENERATE a key in one Azure Key Vault
    instance, BACKUP the key, and then RESTORE it into another Azure Key Vault
    instance. The BACKUP operation may be used to export, in protected form, any
    key type from Azure Key Vault. Individual versions of a key cannot be backed
    up. BACKUP / RESTORE can be performed within geographical boundaries only;
    meaning that a BACKUP from one geographical area cannot be restored to another
    geographical area. For example, a backup from the US geographical area cannot
    be restored in an EU geographical area. This operation requires the key/backup
    permission.
    """
@app.route("/keys/<keyName>/backup", methods=["POST"])
def backup_key(api_version: str, key_name: str) -> Union[BackupKeyResult, ErrorResponse]:
    return _backup_key(api_version, key_name)

    """
    Imports a previously backed up key into Azure Key Vault, restoring the key, its
    key identifier, attributes and access control policies. The RESTORE operation
    may be used to import a previously backed up key. Individual versions of a key
    cannot be restored. The key is restored in its entirety with the same key name
    as it had when it was backed up. If the key name is not available in the target
    Key Vault, the RESTORE operation will be rejected. While the key name is
    retained during restore, the final key identifier will change if the key is
    restored to a different vault. Restore will restore all versions and preserve
    version identifiers. The RESTORE operation is subject to security constraints:
    The target Key Vault must be owned by the same Microsoft Azure Subscription as
    the source Key Vault The user must have RESTORE permission in the target Key
    Vault. This operation requires the keys/restore permission.
    """
@app.route("/keys/restore", methods=["POST"])
def restore_key(api_version: str, parameters: KeyRestoreParameters) -> Union[KeyBundle, ErrorResponse]:
    return _restore_key(api_version, parameters)

    """
    The ENCRYPT operation encrypts an arbitrary sequence of bytes using an
    encryption key that is stored in Azure Key Vault. Note that the ENCRYPT
    operation only supports a single block of data, the size of which is dependent
    on the target key and the encryption algorithm to be used. The ENCRYPT
    operation is only strictly necessary for symmetric keys stored in Azure Key
    Vault since protection with an asymmetric key can be performed using public
    portion of the key. This operation is supported for asymmetric keys as a
    convenience for callers that have a key-reference but do not have access to the
    public key material. This operation requires the keys/encrypt permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/encrypt", methods=["POST"])
def encrypt(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    return _encrypt(api_version, key_name, key_version, parameters)

    """
    The DECRYPT operation decrypts a well-formed block of ciphertext using the
    target encryption key and specified algorithm. This operation is the reverse of
    the ENCRYPT operation; only a single block of data may be decrypted, the size
    of this block is dependent on the target key and the algorithm to be used. The
    DECRYPT operation applies to asymmetric and symmetric keys stored in Azure Key
    Vault since it uses the private portion of the key. This operation requires the
    keys/decrypt permission. Microsoft recommends not to use CBC algorithms for
    decryption without first ensuring the integrity of the ciphertext using an
    HMAC, for example. See
    https://docs.microsoft.com/dotnet/standard/security/vulnerabilities-cbc-mode
    for more information.
    """
@app.route("/keys/<keyName>/<keyVersion>/decrypt", methods=["POST"])
def decrypt(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    return _decrypt(api_version, key_name, key_version, parameters)

    """
    The SIGN operation is applicable to asymmetric and symmetric keys stored in
    Azure Key Vault since this operation uses the private portion of the key. This
    operation requires the keys/sign permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/sign", methods=["POST"])
def sign(api_version: str, key_name: str, key_version: str, parameters: KeySignParameters) -> Union[KeyOperationResult, ErrorResponse]:
    return _sign(api_version, key_name, key_version, parameters)

    """
    The VERIFY operation is applicable to symmetric keys stored in Azure Key Vault.
    VERIFY is not strictly necessary for asymmetric keys stored in Azure Key Vault
    since signature verification can be performed using the public portion of the
    key but this operation is supported as a convenience for callers that only have
    a key-reference and not the public portion of the key. This operation requires
    the keys/verify permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/verify", methods=["POST"])
def verify(api_version: str, key_name: str, key_version: str, parameters: KeyVerifyParameters) -> Union[KeyVerifyResult, ErrorResponse]:
    return _verify(api_version, key_name, key_version, parameters)

    """
    The WRAP operation supports encryption of a symmetric key using a key
    encryption key that has previously been stored in an Azure Key Vault. The WRAP
    operation is only strictly necessary for symmetric keys stored in Azure Key
    Vault since protection with an asymmetric key can be performed using the public
    portion of the key. This operation is supported for asymmetric keys as a
    convenience for callers that have a key-reference but do not have access to the
    public key material. This operation requires the keys/wrapKey permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/wrapkey", methods=["POST"])
def wrap_key(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    return _wrap_key(api_version, key_name, key_version, parameters)

    """
    The UNWRAP operation supports decryption of a symmetric key using the target
    key encryption key. This operation is the reverse of the WRAP operation. The
    UNWRAP operation applies to asymmetric and symmetric keys stored in Azure Key
    Vault since it uses the private portion of the key. This operation requires the
    keys/unwrapKey permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/unwrapkey", methods=["POST"])
def unwrap_key(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    return _unwrap_key(api_version, key_name, key_version, parameters)

    """
    The release key operation is applicable to all key types. The target key must
    be marked exportable. This operation requires the keys/release permission.
    """
@app.route("/keys/<keyName>/<keyVersion>/release", methods=["POST"])
def release(api_version: str, key_name: str, key_version: str, parameters: KeyReleaseParameters) -> Union[KeyReleaseResult, ErrorResponse]:
    return _release(api_version, key_name, key_version, parameters)

    """
    Retrieves a list of the keys in the Key Vault as JSON Web Key structures that
    contain the public part of a deleted key. This operation includes
    deletion-specific information. The Get Deleted Keys operation is applicable for
    vaults enabled for soft-delete. While the operation can be invoked on any
    vault, it will return an error if invoked on a non soft-delete enabled vault.
    This operation requires the keys/list permission.
    """
@app.route("/deletedkeys", methods=["GET"])
def get_deleted_keys(api_version: str, maxresults: int) -> Union[, ErrorResponse]:
    return _get_deleted_keys(api_version, maxresults)

    """
    The Get Deleted Key operation is applicable for soft-delete enabled vaults.
    While the operation can be invoked on any vault, it will return an error if
    invoked on a non soft-delete enabled vault. This operation requires the
    keys/get permission.
    """
@app.route("/deletedkeys/<keyName>", methods=["GET"])
def get_deleted_key(api_version: str, key_name: str) -> Union[DeletedKeyBundle, ErrorResponse]:
    return _get_deleted_key(api_version, key_name)

    """
    The Purge Deleted Key operation is applicable for soft-delete enabled vaults.
    While the operation can be invoked on any vault, it will return an error if
    invoked on a non soft-delete enabled vault. This operation requires the
    keys/purge permission.
    """
@app.route("/deletedkeys/<keyName>", methods=["DELETE"])
def purge_deleted_key(api_version: str, key_name: str) -> Union[None, ErrorResponse]:
    return _purge_deleted_key(api_version, key_name)

    """
    The Recover Deleted Key operation is applicable for deleted keys in soft-delete
    enabled vaults. It recovers the deleted key back to its latest version under
    /keys. An attempt to recover an non-deleted key will return an error. Consider
    this the inverse of the delete operation on soft-delete enabled vaults. This
    operation requires the keys/recover permission.
    """
@app.route("/deletedkeys/<keyName>/recover", methods=["POST"])
def recover_deleted_key(api_version: str, key_name: str) -> Union[KeyBundle, ErrorResponse]:
    return _recover_deleted_key(api_version, key_name)

    """
    The GetKeyRotationPolicy operation returns the specified key policy resources
    in the specified key vault. This operation requires the keys/get permission.
    """
@app.route("/keys/<keyName>/rotationpolicy", methods=["GET"])
def get_key_rotation_policy(api_version: str, key_name: str) -> Union[KeyRotationPolicy, ErrorResponse]:
    return _get_key_rotation_policy(api_version, key_name)

    """
    Set specified members in the key policy. Leave others as undefined. This
    operation requires the keys/update permission.
    """
@app.route("/keys/<keyName>/rotationpolicy", methods=["PUT"])
def update_key_rotation_policy(api_version: str, key_name: str, key_rotation_policy: KeyRotationPolicy) -> Union[KeyRotationPolicy, ErrorResponse]:
    return _update_key_rotation_policy(api_version, key_name, key_rotation_policy)

    """Get the requested number of bytes containing random values from a managed HSM."""
@app.route("/rng", methods=["POST"])
def get_random_bytes(api_version: str, parameters: GetRandomBytesRequest) -> Union[RandomBytes, ErrorResponse]:
    return _get_random_bytes(api_version, parameters)
