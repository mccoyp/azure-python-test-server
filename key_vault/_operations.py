from key_vault import KeyCreateParameters, KeyBundle, KeyImportParameters, DeletedKeyBundle, KeyUpdateParameters, KeyListResult, BackupKeyResult, KeyRestoreParameters, KeyOperationsParameters, KeyOperationResult, KeySignParameters, KeyVerifyParameters, KeyVerifyResult, KeyReleaseParameters, KeyReleaseResult, KeyRotationPolicy, GetRandomBytesRequest, RandomBytes
from azure.core.foundations import ErrorResponse
from typing import Union, Literal

def _create_key(api_version: str, key_name: str, parameters: KeyCreateParameters) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _create_key")

def _rotate_key(api_version: str, key_name: str) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _rotate_key")

def _import_key(api_version: str, key_name: str, parameters: KeyImportParameters) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _import_key")

def _delete_key(api_version: str, key_name: str) -> Union[DeletedKeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _delete_key")

def _update_key(api_version: str, key_name: str, key_version: str, parameters: KeyUpdateParameters) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _update_key")

def _get_key(api_version: str, key_name: str, key_version: str) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_key")

def _get_key_versions(api_version: str, key_name: str, maxresults: int) -> Union[KeyListResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_key_versions")

def _get_keys(api_version: str, maxresults: int) -> Union[, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_keys")

def _backup_key(api_version: str, key_name: str) -> Union[BackupKeyResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _backup_key")

def _restore_key(api_version: str, parameters: KeyRestoreParameters) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _restore_key")

def _encrypt(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _encrypt")

def _decrypt(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _decrypt")

def _sign(api_version: str, key_name: str, key_version: str, parameters: KeySignParameters) -> Union[KeyOperationResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _sign")

def _verify(api_version: str, key_name: str, key_version: str, parameters: KeyVerifyParameters) -> Union[KeyVerifyResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _verify")

def _wrap_key(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _wrap_key")

def _unwrap_key(api_version: str, key_name: str, key_version: str, parameters: KeyOperationsParameters) -> Union[KeyOperationResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _unwrap_key")

def _release(api_version: str, key_name: str, key_version: str, parameters: KeyReleaseParameters) -> Union[KeyReleaseResult, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _release")

def _get_deleted_keys(api_version: str, maxresults: int) -> Union[, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_deleted_keys")

def _get_deleted_key(api_version: str, key_name: str) -> Union[DeletedKeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_deleted_key")

def _purge_deleted_key(api_version: str, key_name: str) -> Union[None, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _purge_deleted_key")

def _recover_deleted_key(api_version: str, key_name: str) -> Union[KeyBundle, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _recover_deleted_key")

def _get_key_rotation_policy(api_version: str, key_name: str) -> Union[KeyRotationPolicy, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_key_rotation_policy")

def _update_key_rotation_policy(api_version: str, key_name: str, key_rotation_policy: KeyRotationPolicy) -> Union[KeyRotationPolicy, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _update_key_rotation_policy")

def _get_random_bytes(api_version: str, parameters: GetRandomBytesRequest) -> Union[RandomBytes, ErrorResponse]:
    # TODO: Implement this
    raise NotImplementedError("Implement _get_random_bytes")
