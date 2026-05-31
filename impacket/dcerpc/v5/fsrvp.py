# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-FSRVP] Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/fortra/impacket/tree/master/tests/SMB_RPC.
#
#   Some calls have helper functions to make it easier for one to use
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#   
#
# Author: Abdul Mhanni
#       

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER
from impacket.dcerpc.v5.dtypes import DWORD, LONG, ULONG, BOOL, LPWSTR, WSTR, GUID, LONGLONG
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_FSRVP = uuidtup_to_bin(('A8E0653C-2744-4389-A61D-7373DF8B2292', '1.0'))

################################################################################
# CONSTANTS
################################################################################

# 2.2.2.1 SHADOW_COPY_ATTRIBUTES
ATTR_PERSISTENT       = 0x00000001
ATTR_NO_AUTO_RECOVERY = 0x00000002
ATTR_NO_AUTO_RELEASE  = 0x00000008
ATTR_NO_WRITERS       = 0x00000010
ATTR_AUTO_RECOVERY    = 0x00400000

# 2.2.2.2 CONTEXT_VALUES
CTX_BACKUP            = 0x00000000
CTX_FILE_SHARE_BACKUP = 0x00000010
CTX_NAS_ROLLBACK      = 0x00000019
CTX_APP_ROLLBACK      = 0x00000009

# 2.2.2.3 SHADOW_COPY_COMPATIBILITY_VALUES
DISABLE_DEFRAG        = 0x00000001
DISABLE_CONTENTINDEX  = 0x00000002

# 2.2.2.4 FSRVP_VERSION_VALUES
FSRVP_RPC_VERSION_1   = 0x00000001

# 2.2.4 Error Codes
FSRVP_E_BAD_STATE                    = 0x80042301
FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS  = 0x80042316
FSRVP_E_NOT_SUPPORTED                = 0x8004230C
FSRVP_E_WAIT_TIMEOUT                 = 0x00000102
FSRVP_E_WAIT_FAILED                  = 0xFFFFFFFF
FSRVP_E_OBJECT_ALREADY_EXISTS        = 0x8004230D
FSRVP_E_OBJECT_NOT_FOUND             = 0x80042308
FSRVP_E_UNSUPPORTED_CONTEXT          = 0x8004231B
FSRVP_E_SHADOWCOPYSET_ID_MISMATCH    = 0x80042501
FSSAGENT_E_TIMEOUT                   = 0x80042500

class DCERPCSessionError(DCERPCException):
    ERROR_MESSAGES = {
        FSRVP_E_BAD_STATE: ("FSRVP_E_BAD_STATE","A method call was invalid because of the state of the server."),
        FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS: ("FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS", "A call was made to either SetContext or StartShadowCopySet while the creation of another shadow copy set is in progress."),
        FSRVP_E_NOT_SUPPORTED: ("FSRVP_E_NOT_SUPPORTED", "The file store which contains the share to be shadow copied is not supported by the server."),
        FSRVP_E_WAIT_TIMEOUT: ("FSRVP_E_WAIT_TIMEOUT", "The wait for a shadow copy commit or expose operation has timed out."),
        FSRVP_E_WAIT_FAILED: ("FSRVP_E_WAIT_FAILED", "The wait for a shadow copy commit or expose operation has failed."),
        FSRVP_E_OBJECT_ALREADY_EXISTS: ("FSRVP_E_OBJECT_ALREADY_EXISTS", "The specified object already exists."),
        FSRVP_E_OBJECT_NOT_FOUND: ("FSRVP_E_OBJECT_NOT_FOUND", "The specified object does not exist."),
        FSRVP_E_UNSUPPORTED_CONTEXT: ("FSRVP_E_UNSUPPORTED_CONTEXT", "The specified context value is invalid."),
        FSRVP_E_SHADOWCOPYSET_ID_MISMATCH: ("FSRVP_E_SHADOWCOPYSET_ID_MISMATCH", "The provided ShadowCopySetId does not exist."),
        FSSAGENT_E_TIMEOUT: ("FSSAGENT_E_TIMEOUT", "The wait for the shadow copy commit operation has timed out."),
    }

    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key in self.ERROR_MESSAGES:
            error_msg_short = self.ERROR_MESSAGES[key][0]
            error_msg_verbose = self.ERROR_MESSAGES[key][1]
            return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'FSRVP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# STRUCTURES
################################################################################

# 2.2.1.1 FSSAGENT_SHARE_MAPPING_1
class FSSAGENT_SHARE_MAPPING_1(NDRSTRUCT):
    structure = (
        ('ShadowCopySetId', GUID),
        ('ShadowCopyId', GUID),
        ('ShareNameUNC', LPWSTR),
        ('ShadowCopyShareName', LPWSTR),
        ('CreationTimestamp', LONGLONG),
    )

class PFSSAGENT_SHARE_MAPPING_1(NDRPOINTER):
    referent = (
        ('Data', FSSAGENT_SHARE_MAPPING_1),
    )

# 2.2.3.1 FSSAGENT_SHARE_MAPPING
class FSSAGENT_SHARE_MAPPING(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        1: ('ShareMapping1', PFSSAGENT_SHARE_MAPPING_1),
    }

class PFSSAGENT_SHARE_MAPPING(NDRPOINTER):
    referent = (
        ('Data', FSSAGENT_SHARE_MAPPING),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 GetSupportedVersion (Opnum 0)
class GetSupportedVersion(NDRCALL):
    opnum = 0
    structure = (
    )

class GetSupportedVersionResponse(NDRCALL):
    structure = (
        ('MinVersion', DWORD),
        ('MaxVersion', DWORD),
        ('ErrorCode', ULONG),
    )

# 3.1.4.2 SetContext (Opnum 1)
class SetContext(NDRCALL):
    opnum = 1
    structure = (
        ('Context', ULONG),
    )

class SetContextResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.3 StartShadowCopySet (Opnum 2)
class StartShadowCopySet(NDRCALL):
    opnum = 2
    structure = (
        ('ClientShadowCopySetId', GUID),
    )

class StartShadowCopySetResponse(NDRCALL):
    structure = (
        ('pShadowCopySetId', GUID),
        ('ErrorCode', ULONG),
    )

# 3.1.4.4 AddToShadowCopySet (Opnum 3)
class AddToShadowCopySet(NDRCALL):
    opnum = 3
    structure = (
        ('ClientShadowCopyId', GUID),
        ('ShadowCopySetId', GUID),
        ('ShareName', WSTR),
    )

class AddToShadowCopySetResponse(NDRCALL):
    structure = (
        ('pShadowCopyId', GUID),
        ('ErrorCode', ULONG),
    )

# 3.1.4.5 CommitShadowCopySet (Opnum 4)
class CommitShadowCopySet(NDRCALL):
    opnum = 4
    structure = (
        ('ShadowCopySetId', GUID),
        ('TimeOutInMilliseconds', ULONG),
    )

class CommitShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.6 ExposeShadowCopySet (Opnum 5)
class ExposeShadowCopySet(NDRCALL):
    opnum = 5
    structure = (
        ('ShadowCopySetId', GUID),
        ('TimeOutInMilliseconds', ULONG),
    )

class ExposeShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.7 RecoveryCompleteShadowCopySet (Opnum 6)
class RecoveryCompleteShadowCopySet(NDRCALL):
    opnum = 6
    structure = (
        ('ShadowCopySetId', GUID),
    )

class RecoveryCompleteShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.8 AbortShadowCopySet (Opnum 7)
class AbortShadowCopySet(NDRCALL):
    opnum = 7
    structure = (
        ('ShadowCopySetId', GUID),
    )

class AbortShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.9 IsPathSupported (Opnum 8)
class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ('ShareName', WSTR),
    )

class IsPathSupportedResponse(NDRCALL):
    structure = (
        ('SupportedByThisProvider', BOOL),
        ('OwnerMachineName', LPWSTR),
        ('ErrorCode', ULONG),
    )

# 3.1.4.10 IsPathShadowCopied (Opnum 9)
class IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (
        ('ShareName', WSTR),
    )

class IsPathShadowCopiedResponse(NDRCALL):
    structure = (
        ('ShadowCopyPresent', BOOL),
        ('ShadowCopyCompatibility', LONG),
        ('ErrorCode', ULONG),
    )

# 3.1.4.11 GetShareMapping (Opnum 10)
class GetShareMapping(NDRCALL):
    opnum = 10
    structure = (
        ('ShadowCopyId', GUID),
        ('ShadowCopySetId', GUID),
        ('ShareName', WSTR),
        ('Level', DWORD),
    )

class GetShareMappingResponse(NDRCALL):
    structure = (
        ('ShareMapping', FSSAGENT_SHARE_MAPPING),
        ('ErrorCode', ULONG),
    )

# 3.1.4.12 DeleteShareMapping (Opnum 11)
class DeleteShareMapping(NDRCALL):
    opnum = 11
    structure = (
        ('ShadowCopySetId', GUID),
        ('ShadowCopyId', GUID),
        ('ShareName', WSTR),
    )

class DeleteShareMappingResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.1.4.13 PrepareShadowCopySet (Opnum 12)
class PrepareShadowCopySet(NDRCALL):
    opnum = 12
    structure = (
        ('ShadowCopySetId', GUID),
        ('TimeOutInMilliseconds', ULONG),
    )

class PrepareShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0  : (GetSupportedVersion, GetSupportedVersionResponse),
    1  : (SetContext, SetContextResponse),
    2  : (StartShadowCopySet, StartShadowCopySetResponse),
    3  : (AddToShadowCopySet, AddToShadowCopySetResponse),
    4  : (CommitShadowCopySet, CommitShadowCopySetResponse),
    5  : (ExposeShadowCopySet, ExposeShadowCopySetResponse),
    6  : (RecoveryCompleteShadowCopySet, RecoveryCompleteShadowCopySetResponse),
    7  : (AbortShadowCopySet, AbortShadowCopySetResponse),
    8  : (IsPathSupported, IsPathSupportedResponse),
    9  : (IsPathShadowCopied, IsPathShadowCopiedResponse),
    10 : (GetShareMapping, GetShareMappingResponse),
    11 : (DeleteShareMapping, DeleteShareMappingResponse),
    12 : (PrepareShadowCopySet, PrepareShadowCopySetResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hGetSupportedVersion(dce):
    request = GetSupportedVersion()
    return dce.request(request)

def hSetContext(dce, context):
    request = SetContext()
    request['Context'] = context
    return dce.request(request)

def hStartShadowCopySet(dce, clientShadowCopySetId):
    request = StartShadowCopySet()
    request['ClientShadowCopySetId'] = clientShadowCopySetId
    return dce.request(request)

def hAddToShadowCopySet(dce, clientShadowCopyId, shadowCopySetId, shareName):
    request = AddToShadowCopySet()
    request['ClientShadowCopyId'] = clientShadowCopyId
    request['ShadowCopySetId'] = shadowCopySetId
    request['ShareName'] = shareName
    return dce.request(request)

def hCommitShadowCopySet(dce, shadowCopySetId, timeOutInMilliseconds=60000):
    request = CommitShadowCopySet()
    request['ShadowCopySetId'] = shadowCopySetId
    request['TimeOutInMilliseconds'] = timeOutInMilliseconds
    return dce.request(request)

def hExposeShadowCopySet(dce, shadowCopySetId, timeOutInMilliseconds=1800000):
    request = ExposeShadowCopySet()
    request['ShadowCopySetId'] = shadowCopySetId
    request['TimeOutInMilliseconds'] = timeOutInMilliseconds
    return dce.request(request)

def hRecoveryCompleteShadowCopySet(dce, shadowCopySetId):
    request = RecoveryCompleteShadowCopySet()
    request['ShadowCopySetId'] = shadowCopySetId
    return dce.request(request)

def hAbortShadowCopySet(dce, shadowCopySetId):
    request = AbortShadowCopySet()
    request['ShadowCopySetId'] = shadowCopySetId
    return dce.request(request)

def hIsPathSupported(dce, shareName):
    request = IsPathSupported()
    request['ShareName'] = shareName
    return dce.request(request)

def hIsPathShadowCopied(dce, shareName):
    request = IsPathShadowCopied()
    request['ShareName'] = shareName
    return dce.request(request)

def hGetShareMapping(dce, shadowCopyId, shadowCopySetId, shareName, level=1):
    request = GetShareMapping()
    request['ShadowCopyId'] = shadowCopyId
    request['ShadowCopySetId'] = shadowCopySetId
    request['ShareName'] = shareName
    request['Level'] = level
    return dce.request(request)

def hDeleteShareMapping(dce, shadowCopySetId, shadowCopyId, shareName):
    request = DeleteShareMapping()
    request['ShadowCopySetId'] = shadowCopySetId
    request['ShadowCopyId'] = shadowCopyId
    request['ShareName'] = shareName
    return dce.request(request)

def hPrepareShadowCopySet(dce, shadowCopySetId, timeOutInMilliseconds=1800000):
    request = PrepareShadowCopySet()
    request['ShadowCopySetId'] = shadowCopySetId
    request['TimeOutInMilliseconds'] = timeOutInMilliseconds
    return dce.request(request)