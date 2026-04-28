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
#   NEGOEX - SPNEGO Extended Negotiation Security Mechanism, is provided to
#   allow SPNEGO to negotiate authentication mechanisms that require more
#   complex exchanges than the simple OID exchange SPNEGO and to address
#   some of SPNEGO's limitations around use of OID as a pure method of selection of authentication mechanisisms.
#   Additionally, NEGOEX provides a new type of exchange, in the form of metadata tokens that provide additional
#   information about each of the proposed/exchanged authentication mechanisims. 
# 
#
# References:
#   [MS-NEGOEX]           - SPNEGO Extended Negotiation Security Mechanism
#                           (v20240423)
#   [IETFDRAFT-NEGOEX-04] - draft-zhu-negoex-04 (January 2011)
#   [RFC3961]             - Encryption and Checksum Specifications for
#                           Kerberos 5 (used by the VERIFY message)
#
# Author:
# Abdul Mhanni

from __future__ import division
from __future__ import print_function

from enum import IntEnum
import os
import uuid

from impacket import LOG
from impacket.structure import Structure
from impacket.krb5.crypto import Key, make_checksum



# [MS-NEGOEX] 2.2.3 - MESSAGE_SIGNATURE: little-endian "NEGOEXTS" (0x535458454f47454e)
MESSAGE_SIGNATURE = b'NEGOEXTS'

# OID for NEGOEX inside SPNEGO (1.3.6.1.4.1.311.2.2.30). Mirrors the entry
# in impacket.spnego.MechTypes, repeated here so consumers don't need a
# circular import.
NEGOEX_OID = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e'

# [MS-NEGOEX] 2.2.3 / draft-zhu-negoex-04 
CHECKSUM_SCHEME_RFC3961 = 1
NEGOEX_PROTOCOL_VERSION = 0

# [MS-NEGOEX] 2.2.3 - Alert types and reason codes. Only one alert type
# (ALERT_TYPE_PULSE) and one reason (ALERT_VERIFY_NO_KEY) are currently
# defined by the spec. To extend, add a new ALERT_TYPE_* constant here and
# add a corresponding entry to _ALERT_BODY_PARSERS below.
ALERT_TYPE_PULSE = 1
ALERT_VERIFY_NO_KEY = 1

# draft-zhu-negoex-04 §7.7 - RFC 3961 key usage numbers used when computing
# the VERIFY checksum. 23 when signed by the initiator, 25 when signed by
# the acceptor.
NEGOEX_KEYUSAGE_INITIATOR = 23
NEGOEX_KEYUSAGE_ACCEPTOR = 25

# Wire-format header sizes. cbHeaderLength is the per-message header,
# excluding any variable-length payload.
#
# MESSAGE_HEADER          : 8 sig + 4 type + 4 seq + 4 cbHdr + 4 cbMsg + 16 GUID = 40
# NEGO_MESSAGE header     : 40 + 32 (Random) + 8 (ProtocolVersion) +
#                           8 (AUTH_SCHEME_VECTOR) + 8 (EXTENSION_VECTOR) = 96
# EXCHANGE_MESSAGE header : 40 + 16 (AUTH_SCHEME) + 8 (BYTE_VECTOR) = 64
# VERIFY_MESSAGE header   : 40 + 16 (AUTH_SCHEME) + 20 (CHECKSUM) + 4 pad = 80
#                           ([MS-NEGOEX] 2.2.6.5 / draft §A define VERIFY
#                           with a 76-byte header; Windows implementations
#                           ULONG-align the trailing payload, so cbHeaderLength
#                           is always observed as 80 on the wire. We follow
#                           Windows for interop.)
# ALERT_MESSAGE header    : 40 + 16 (AUTH_SCHEME) + 4 (ErrorCode) +
#                           6 (ALERT_VECTOR) + 2 pad = 68
#                           (ALERT_VECTOR is 4+2=6 bytes per spec; the 2-byte
#                           pad is again Windows ULONG-alignment for the
#                           trailing payload, not in the IETF draft.)
# CHECKSUM struct         : 4 cbHdr + 4 scheme + 4 type + 8 BYTE_VECTOR = 20
HEADER_SIZE = 40
NEGO_HEADER_SIZE = 96
EXCHANGE_HEADER_SIZE = 64
VERIFY_HEADER_SIZE = 80
ALERT_HEADER_SIZE = 68
CHECKSUM_HEADER_SIZE = 20

AUTH_SCHEME_SIZE = 16   ##AUTH_SCHEME is a GUID (16 bytes). [MS-NEGOEX] 2.2.2, [MS-DTYP] 2.3.4.2.

EXTENSION_SIZE = 12     # [MS-NEGOEX] 2.2.5.1.4

# Wire size of one ALERT struct: ULONG + BYTE_VECTOR = 4 + 8 = 12.
# draft-zhu-negoex-04 Appendix A (ALERT layout) and BYTE_VECTOR define it as above formula.
ALERT_SIZE = 12 


class MESSAGE_TYPE(IntEnum):
    # [MS-NEGOEX] 2.2.6.1
    INITIATOR_NEGO = 0
    ACCEPTOR_NEGO = 1
    INITIATOR_META_DATA = 2
    ACCEPTOR_META_DATA = 3
    CHALLENGE = 4
    AP_REQUEST = 5
    VERIFY = 6
    ALERT = 7


# Message types that in the EXCHANGE_MESSAGE.
EXCHANGE_MESSAGE_TYPES = (
    MESSAGE_TYPE.INITIATOR_META_DATA,
    MESSAGE_TYPE.ACCEPTOR_META_DATA,
    MESSAGE_TYPE.CHALLENGE,
    MESSAGE_TYPE.AP_REQUEST,
)

# Internal helpers

def _normalizeGuid(value):
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, bytes) and len(value) == 16:
        return uuid.UUID(bytes_le=value)
    if isinstance(value, str):
        return uuid.UUID(value)
    raise NegoExError('Invalid GUID value: %r' % value)


def _normalizeGuidBytes(value):
    return _normalizeGuid(value).bytes_le


def _asBytes(value, name):
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise NegoExError('%s must be bytes or str, got %r' % (name, type(value)))


def _checkHeader(header, expectedHeaderLen, actualLen, name):
    cbHeader = header['cbHeaderLength']
    cbMessage = header['cbMessageLength']

    if cbHeader != expectedHeaderLen:
        raise NegoExParseError(
            '%s.cbHeaderLength expected %d, got %d' % (name, expectedHeaderLen, cbHeader),
            field='%s.cbHeaderLength' % name,
        )
    if cbMessage < cbHeader:
        raise NegoExParseError(
            '%s.cbMessageLength smaller than cbHeaderLength' % name,
            field='%s.cbMessageLength' % name,
        )
    if cbMessage != actualLen:
        raise NegoExParseError(
            '%s.cbMessageLength = %d but slice is %d bytes' % (name, cbMessage, actualLen),
            field='%s.cbMessageLength' % name,
        )


def _slice(data, offset, length, name, minimumOffset=0):
    if length == 0:
        return b''
    if offset == 0:
        raise NegoExParseError('%s has length but zero offset' % name, field=name)
    if offset < minimumOffset:
        raise NegoExParseError('%s offset is before payload' % name, offset=offset, field=name)
    if offset > len(data) or length > len(data) - offset:
        raise NegoExParseError('%s extends beyond message' % name, offset=offset, field=name)
    return data[offset:offset + length]


def _sliceVector(data, offset, count, itemSize, name, minimumOffset=0):
    if count == 0:
        return b''
    return _slice(data, offset, count * itemSize, name, minimumOffset)


def _messageHeader(messageType, seqNum, conversationId, headerLen, messageLen):
    """Helper function to create a MESSAGE_HEADER struct. This is repeated across message types
    and so to ensure consistency we create a single helper for it. """
    header = MessageHeader()
    header['Signature'] = MESSAGE_SIGNATURE
    header['MessageType'] = messageType
    header['SequenceNum'] = seqNum
    header['cbHeaderLength'] = headerLen
    header['cbMessageLength'] = messageLen
    header['ConversationId'] = _normalizeGuidBytes(conversationId)
    return header



class MessageHeader(Structure):
    # [MS-NEGOEX] 2.2.6.2
    structure = (
        ('Signature', '8s=b"NEGOEXTS"'),
        ('MessageType', '<L=0'),
        ('SequenceNum', '<L=0'),
        ('cbHeaderLength', '<L=0'),
        ('cbMessageLength', '<L=0'),
        ('ConversationId', '16s=""'),
    )

    def fromString(self, data):
        if len(data) < HEADER_SIZE:
            raise NegoExParseError('Truncated MESSAGE_HEADER', field='Header')
        Structure.fromString(self, data)
        if self['Signature'] != MESSAGE_SIGNATURE:
            raise NegoExParseError('Invalid NEGOEX signature', field='Header.Signature')


class Checksum(Structure):
    # [MS-NEGOEX] 2.2.5.1.3 - cbHeaderLength is always 20.
    structure = (
        ('cbHeaderLength', '<I=20'),
        ('ChecksumScheme', '<I=1'),
        ('ChecksumType', '<I=0'),
        ('ChecksumOffset', '<I=0'),
        ('ChecksumLength', '<I=0'),
    )


class Extension(Structure):
    # [MS-NEGOEX] 2.2.5.1.4
    structure = (
        ('ExtensionType', '<I=0'),
        ('ByteArrayOffset', '<I=0'),
        ('ByteArrayLength', '<I=0'),
    )

    def __init__(self, data=None):
        self.ExtensionValue = b''
        Structure.__init__(self, data)

    def isCritical(self):
        # [MS-NEGOEX] 2.2.5.1.4: "All negative extension types (the highest
        # bit is set to 1) are critical." ExtensionType is encoded as ULONG,
        # so we test the high bit directly rather than treat it as signed.
        return (self['ExtensionType'] & 0x80000000) != 0
        #also note if we recieve an unknown critical extension type, we MUST fail the negoex exchange per [MS-NEGOEX] 2.2.5.1.4

    def isKnown(self):
        #As of now, neither IETF draft-zhu-o4 nor ms-negoex define any extension types in specific.
        #We should however have a way to track known ones because we need to ensure IF we get a "critical" extension we dont know we need to reject
        return NotImplemented

class Alert(Structure):
    
    structure = (
        ('AlertType', '<I=1'),
        ('ByteArrayOffset', '<I=0'),
        ('ByteArrayLength', '<I=0'),
    )

    def __init__(self, data=None):
        # Raw, unparsed alert body. Always present.
        self.AlertValue = b''
        # Type-specific decoded body, populated by _decodeAlertBody when the
        # AlertType is one we recognise. None means either the body has not
        # been decoded yet or the AlertType is unknown.
        self.AlertReason = None
        Structure.__init__(self, data)


class AlertPulse(Structure):
    
    structure = (
        ('cbHeaderLength', '<I=8'),
        ('Reason', '<I=1'),
    )


def _parseAlertPulse(body):
    if len(body) < 8:
        raise NegoExParseError('Truncated ALERT_PULSE body', field='AlertValue')
    pulse = AlertPulse(body[:8])
    if pulse['cbHeaderLength'] != 8:
        raise NegoExParseError('Invalid ALERT_PULSE.cbHeaderLength: %d' % pulse['cbHeaderLength'], field='AlertPulse.cbHeaderLength')
    return pulse['Reason']


# table for type-specific alert body parsers. To support a new
# AlertType, add a constant above and an entry here that returns the
# decoded value; Alert.AlertReason will be populated automatically.
_ALERT_BODY_PARSERS = {
    ALERT_TYPE_PULSE: _parseAlertPulse,
}


def _decodeAlertBody(alert):
    parser = _ALERT_BODY_PARSERS.get(alert['AlertType'])
    if parser is None:
        # Unknown alert type. Spec doesn't mandate failure; leave AlertValue
        # raw and let the consumer inspect it if they care.
        LOG.debug('NEGOEX: unknown ALERT type 0x%x, leaving body raw' % alert['AlertType'])
        return
    try:
        alert.AlertReason = parser(alert.AlertValue)
    except NegoExParseError as e:
        LOG.debug('NEGOEX: failed to decode ALERT body: %s' % e)


class AuthSchemeVector(Structure):
    # [MS-NEGOEX] 2.2.5.2.2: 4-byte offset + 2-byte count. The trailing 2
    # bytes are ULONG-alignment padding observed on the wire.
    structure = (
        ('ArrayOffset', '<I=0'),
        ('Count', '<H=0'),
        ('Pad', '2s=""'),
    )


class ExtensionVector(Structure):
    # [MS-NEGOEX] 2.2.5.2.4: 4-byte offset + 2-byte count + 2-byte alignment pad.
    structure = (
        ('ArrayOffset', '<I=0'),
        ('Count', '<H=0'),
        ('Pad', '2s=""'),
    )


class NegoMessage(Structure):
    # [MS-NEGOEX] 2.2.6.3
    structure = (
        ('Header', ':', MessageHeader),
        ('Random', '32s=""'),
        ('ProtocolVersion', '<Q=0'),
        ('AuthSchemes', ':', AuthSchemeVector),
        ('Extensions', ':', ExtensionVector),
        ('Payload', ':'),
    )

    def __init__(self, data=None):
        self._authSchemes = []
        self._extensions = []
        Structure.__init__(self, data)

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], NEGO_HEADER_SIZE, len(data), 'NegoMessage.Header')

        if self['Header']['MessageType'] not in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            raise NegoExParseError('Invalid NEGO_MESSAGE type: %r' % self['Header']['MessageType'])
        if self['ProtocolVersion'] != NEGOEX_PROTOCOL_VERSION:
            raise NegoExParseError('Unsupported NEGOEX protocol version: %r' % self['ProtocolVersion'])
            #spec specifies we should fail if we encounter a different version.

        authBlob = _sliceVector(data, self['AuthSchemes']['ArrayOffset'],self['AuthSchemes']['Count'], AUTH_SCHEME_SIZE, 'AuthSchemes',NEGO_HEADER_SIZE)
        self._authSchemes = [uuid.UUID(bytes_le=authBlob[i:i + AUTH_SCHEME_SIZE]) for i in range(0, len(authBlob), AUTH_SCHEME_SIZE)]

        extBlob = _sliceVector(
            data,
            self['Extensions']['ArrayOffset'],
            self['Extensions']['Count'],
            EXTENSION_SIZE,
            'Extensions',
            NEGO_HEADER_SIZE,
        )
        self._extensions = []
        for i in range(0, len(extBlob), EXTENSION_SIZE):
            ext = Extension(extBlob[i:i + EXTENSION_SIZE])
            ext.ExtensionValue = _slice(data, ext['ByteArrayOffset'], ext['ByteArrayLength'], 'ExtensionValue', NEGO_HEADER_SIZE)
            self._extensions.append(ext)

    def getAuthSchemeList(self):
        return self._authSchemes

    def getExtensionList(self):
        return self._extensions


class ExchangeMessage(Structure):
    # [MS-NEGOEX] 2.2.6.4
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('ExchangeOffset', '<I=0'),
        ('ExchangeLength', '<I=0'),
        ('Exchange', ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], EXCHANGE_HEADER_SIZE, len(data), 'ExchangeMessage.Header')

        try:
            msgType = MESSAGE_TYPE(self['Header']['MessageType'])
        except ValueError:
            raise NegoExParseError('Invalid EXCHANGE_MESSAGE type: %r' % self['Header']['MessageType'])
        if msgType not in EXCHANGE_MESSAGE_TYPES:
            raise NegoExParseError('Invalid EXCHANGE_MESSAGE type: %r' % self['Header']['MessageType'])

        self['Exchange'] = _slice(data, self['ExchangeOffset'], self['ExchangeLength'], 'Exchange', EXCHANGE_HEADER_SIZE)


class VerifyMessage(Structure):
    # [MS-NEGOEX] 2.2.6.5 
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('CHeader', ':', Checksum),
        # 4-byte alignment pad, see VERIFY_HEADER_SIZE comment above.
        ('Pad', '4s=""'),
        ('ChecksumValue', ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], VERIFY_HEADER_SIZE, len(data), 'VerifyMessage.Header')

        if self['Header']['MessageType'] != MESSAGE_TYPE.VERIFY:
            raise NegoExParseError('Invalid VERIFY_MESSAGE type: %r' % self['Header']['MessageType'])
        if self['CHeader']['cbHeaderLength'] != CHECKSUM_HEADER_SIZE:
            raise NegoExParseError('Invalid CHECKSUM header length', field='CHeader.cbHeaderLength')
        if self['CHeader']['ChecksumScheme'] != CHECKSUM_SCHEME_RFC3961:
            raise NegoExParseError('Unsupported CHECKSUM scheme', field='CHeader.ChecksumScheme')

        self['ChecksumValue'] = _slice(
            data,
            self['CHeader']['ChecksumOffset'],
            self['CHeader']['ChecksumLength'],
            'ChecksumValue',
            VERIFY_HEADER_SIZE,
        )


class AlertMessage(Structure):
    # [MS-NEGOEX] 2.2.6.6
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('ErrorCode', '<I=0'),
        ('AlertArrayOffset', '<I=0'),
        ('AlertCount', '<H=0'),
        # ALERT_VECTOR is 4+2 bytes per spec; the 2-byte pad here is the
        # ULONG-alignment Windows applies before the payload starts.
        ('AlertPad', '2s=""'),
        ('Payload', ':'),
    )

    def __init__(self, data=None):
        self._alerts = []
        Structure.__init__(self, data)

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], ALERT_HEADER_SIZE, len(data), 'AlertMessage.Header')

        if self['Header']['MessageType'] != MESSAGE_TYPE.ALERT:
            raise NegoExParseError('Invalid ALERT_MESSAGE type: %r' % self['Header']['MessageType'])

        alertBlob = _sliceVector(
            data,
            self['AlertArrayOffset'],
            self['AlertCount'],
            ALERT_SIZE,
            'Alerts',
            ALERT_HEADER_SIZE,
        )
        self._alerts = []
        for i in range(0, len(alertBlob), ALERT_SIZE):
            alert = Alert(alertBlob[i:i + ALERT_SIZE])
            alert.AlertValue = _slice(data, alert['ByteArrayOffset'], alert['ByteArrayLength'], 'AlertValue', ALERT_HEADER_SIZE)
            # Decode the body when the AlertType is one we recognise. The
            # decoded value lands on alert.AlertReason; the raw bytes stay
            # on alert.AlertValue either way so consumers always have both.
            _decodeAlertBody(alert)
            self._alerts.append(alert)

    def getAlertList(self):
        return self._alerts


class ParsedMessage(object):
    """One element of the list returned by parseNegoExToken.

    message_type is always set to the raw integer from the wire.
    message is the parsed Structure, or None if the type was unknown.
    raw_data is the exact bytes for that message (including header), used
    by NegoExContext when computing VERIFY checksums."""

    def __init__(self, messageType, message, offset, rawData):
        self.message_type = messageType
        self.message = message
        self.offset = offset
        self.raw_data = rawData



def parseNegoExToken(data):
    """Split a concatenated NEGOEX token into its component messages.

    Per [MS-NEGOEX] 3.1.5.1, a context-level token is one or more NEGOEX
    messages concatenated together. Each message advertises its own length
    in the header, so we traverse until consumed.
    """
    messages = []
    offset = 0

    while offset < len(data):
        if len(data) - offset < HEADER_SIZE:
            raise NegoExParseError('Truncated NEGOEX header', offset=offset, field='Header')

        header = MessageHeader(data[offset:offset + HEADER_SIZE])
        msgLength = header['cbMessageLength']
        if msgLength < HEADER_SIZE:
            raise NegoExParseError('Invalid cbMessageLength: %d' % msgLength, offset=offset, field='Header.cbMessageLength')
        if msgLength > len(data) - offset:
            raise NegoExParseError('Truncated NEGOEX message', offset=offset, field='Header.cbMessageLength')

        msgData = data[offset:offset + msgLength]
        rawType = header['MessageType']

        try:
            msgType = MESSAGE_TYPE(rawType)
        except ValueError:
            LOG.warning('Unknown NEGOEX MessageType: %r' % rawType)
            messages.append(ParsedMessage(rawType, None, offset, msgData))
            offset += msgLength
            continue

        if msgType in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            message = NegoMessage(msgData)
        elif msgType in EXCHANGE_MESSAGE_TYPES:
            message = ExchangeMessage(msgData)
        elif msgType == MESSAGE_TYPE.VERIFY:
            message = VerifyMessage(msgData)
        elif msgType == MESSAGE_TYPE.ALERT:
            message = AlertMessage(msgData)
        else:
            raise NegoExParseError('Unhandled NEGOEX MessageType: %r' % rawType, offset=offset)

        messages.append(ParsedMessage(msgType, message, offset, msgData))
        offset += msgLength

    return messages


def createNegoMessage(messageType, seqNum, conversationId, authSchemes, extensions=None):

    if messageType not in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
        raise NegoExError('Invalid message type for NEGO_MESSAGE: %r' % messageType)

    authParts = [_normalizeGuidBytes(scheme) for scheme in authSchemes]
    authCount = len(authParts)
    authPayload = b''.join(authParts)
    authOffset = NEGO_HEADER_SIZE if authCount else 0

    extensions = extensions or []
    extCount = len(extensions)
    extOffset = NEGO_HEADER_SIZE + len(authPayload) if extCount else 0
    extHeaders = b''
    extValues = b''

    if extCount:
        valueBase = extOffset + extCount * EXTENSION_SIZE
        for extType, extValue in extensions:
            extValue = _asBytes(extValue, 'extension value')
            ext = Extension()
            ext['ExtensionType'] = extType
            ext['ByteArrayOffset'] = valueBase + len(extValues) if extValue else 0
            ext['ByteArrayLength'] = len(extValue)
            extHeaders += ext.getData()
            extValues += extValue

    payload = authPayload + extHeaders + extValues

    msg = NegoMessage()
    msg['Header'] = _messageHeader(messageType, seqNum, conversationId, NEGO_HEADER_SIZE, NEGO_HEADER_SIZE + len(payload))
    msg['Random'] = os.urandom(32)
    msg['ProtocolVersion'] = NEGOEX_PROTOCOL_VERSION
    msg['AuthSchemes'] = AuthSchemeVector()
    msg['AuthSchemes']['ArrayOffset'] = authOffset
    msg['AuthSchemes']['Count'] = authCount
    msg['Extensions'] = ExtensionVector()
    msg['Extensions']['ArrayOffset'] = extOffset
    msg['Extensions']['Count'] = extCount
    msg['Payload'] = payload
    return msg.getData()


def createExchangeMessage(messageType, seqNum, conversationId, authScheme, exchangeData):
    if messageType not in EXCHANGE_MESSAGE_TYPES:
        raise NegoExError('Invalid message type for EXCHANGE_MESSAGE: %r' % messageType)

    exchangeData = _asBytes(exchangeData, 'exchangeData')
    exchangeLen = len(exchangeData)

    msg = ExchangeMessage()
    msg['Header'] = _messageHeader(messageType, seqNum, conversationId, EXCHANGE_HEADER_SIZE, EXCHANGE_HEADER_SIZE + exchangeLen)
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['ExchangeOffset'] = EXCHANGE_HEADER_SIZE if exchangeLen else 0
    msg['ExchangeLength'] = exchangeLen
    msg['Exchange'] = exchangeData
    return msg.getData()


def createVerifyMessage(seqNum, conversationId, authScheme, checksumValue, checksumType):
    checksumValue = _asBytes(checksumValue, 'checksumValue')

    msg = VerifyMessage()
    msg['Header'] = _messageHeader(MESSAGE_TYPE.VERIFY, seqNum, conversationId, VERIFY_HEADER_SIZE,VERIFY_HEADER_SIZE + len(checksumValue))
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['CHeader'] = Checksum()
    msg['CHeader']['cbHeaderLength'] = CHECKSUM_HEADER_SIZE
    msg['CHeader']['ChecksumScheme'] = CHECKSUM_SCHEME_RFC3961
    msg['CHeader']['ChecksumType'] = checksumType
    msg['CHeader']['ChecksumOffset'] = VERIFY_HEADER_SIZE if checksumValue else 0
    msg['CHeader']['ChecksumLength'] = len(checksumValue)
    msg['Pad'] = b'\x00' * 4
    msg['ChecksumValue'] = checksumValue
    return msg.getData()


def createAlertMessage(seqNum, conversationId, authScheme, errorCode=0, reason=ALERT_VERIFY_NO_KEY):
    pulse = AlertPulse()
    pulse['Reason'] = reason
    pulseData = pulse.getData()

    alert = Alert()
    alert['AlertType'] = ALERT_TYPE_PULSE
    alert['ByteArrayOffset'] = ALERT_HEADER_SIZE + ALERT_SIZE  
    alert['ByteArrayLength'] = len(pulseData)

    payload = alert.getData() + pulseData

    msg = AlertMessage()
    msg['Header'] = _messageHeader(
        MESSAGE_TYPE.ALERT,
        seqNum,
        conversationId,
        ALERT_HEADER_SIZE,
        ALERT_HEADER_SIZE + len(payload),
    )
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['ErrorCode'] = errorCode
    msg['AlertArrayOffset'] = ALERT_HEADER_SIZE
    msg['AlertCount'] = 1
    msg['Payload'] = payload
    return msg.getData()



class NegoExAuthScheme(object):
    """Base class consumers extend to plug auth mechanisms into NEGOEX. Right now only PKU2U and cloud AP but more will be expected from microsoft.

    Contract for the methods below:

      getAuthSchemeId():
          Required. Return this scheme's AUTH_SCHEME GUID, as a uuid.UUID,
          a 16-byte little-endian bytes value, or a string accepted by
          uuid.UUID(). [MS-NEGOEX] 2.2.2.

      queryMetaData(isInitiator):
          Optional. Return bytes (the metadata token to send) or None if
          this scheme has no metadata to contribute. a mechanism that carries
          no metadata or that theres no additional metadata to provide etc. 
          Raising NegoExError will lead to this scheme being dropped from the mutually
         supported list. ([MS-NEGOEX] 3.1.5.8.1)

      exchangeMetaData(isInitiator, metadata):
          Optional. Called when a peer metadata token arrives for this
          scheme. Return True to keep the scheme in our mutually-supported list, False to remove
          from the mutually-supported list. ([MS-NEGOEX] 3.1.5.8.2)

      getVerifyKey():
          Optional. Return (keyBytes, enctype, checksumType) once the
          mechanism has established keying material, or None if no key is
          available yet. NEGOEX uses this for the VERIFY message
          (draft-zhu-negoex-04 §7.7).
    """

    def getAuthSchemeId(self):
        raise NotImplementedError

    def queryMetaData(self, isInitiator):
        return None

    def exchangeMetaData(self, isInitiator, metadata):
        return True

    def getVerifyKey(self):
        return None



class NegoExContext(object):
    """Drives a NEGOEX negotiation as either initiator or acceptor.
    """

    def __init__(self, isInitiator=True):
        #Since mostly impacket is used for pentesting, safe to assume the person running will be iniator
        self.isInitiator = isInitiator
        #16-byte conversation ID, generated by the initiator and echoed by the acceptor in all messages. [MS-NEGOEX] 2.2.3 
        self.conversationId = None
        #The scheme selected for use for the exchange.
        self.selectedScheme = None
        self._seqNum = 0
        #The schemes that have been registered by the runner to be offered to the acceptor
        self._authSchemes = {}
        #The order in which the exchange will decide which scheme will end up being selected.
        self._authSchemeOrder = []
        #Schemes that are mutually supported by the iniator and acceptor
        self._mutualSchemes = []
        #Used to track all messages sent and recieved during the whole exchaange for use in the VERIFY msg checkum creation
        self._messageHistory = []
        #flag to track if the current executor sent a VERIFY message
        self._verifySent = False
        #Flag to track if we were sent a verfiy message by the peer.
        self._verifyReceived = False

  

    def registerAuthScheme(self, scheme):
        schemeId = _normalizeGuid(scheme.getAuthSchemeId())
        self._authSchemes[schemeId] = scheme
        self._authSchemeOrder.append(schemeId)

    

    def createInitialToken(self, optimisticToken=None):
        """Build the initiator's first NEGOEX token.

        Per [MS-NEGOEX] 3.1.5.5.1, the optimistic token, when present at least
        applies to the first registered scheme and register schemes in
        decreasing order of preference.
        """
        if not self.isInitiator:
            raise NegoExError('createInitialToken() is for the initiator only')

        self.conversationId = os.urandom(16)
        authSchemes = []
        metadataParts = []

        for schemeId in list(self._authSchemeOrder):
            try:
                metadata = self._authSchemes[schemeId].queryMetaData(True)
            except NegoExError as e:
                LOG.debug('NEGOEX: queryMetaData failed for %s: %s' % (schemeId, e))
                continue

            authSchemes.append(schemeId)
            if metadata:
                metadataParts.append((schemeId, metadata))

        self._authSchemeOrder = authSchemes

        tokenParts = [createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, self._nextSeq(), self.conversationId, authSchemes)]

        for schemeId, metadata in metadataParts:
            tokenParts.append(
                createExchangeMessage(
                    MESSAGE_TYPE.INITIATOR_META_DATA,
                    self._nextSeq(),
                    self.conversationId,
                    schemeId,
                    metadata,
                )
            )
        #note that if we dont have the optimistic token, we would not preform a round trip.
        #we would cut down on the traffic since if the acceptor the scheme attached, we would jump to challenge part
        if optimisticToken and authSchemes:
            tokenParts.append(
                createExchangeMessage(
                    MESSAGE_TYPE.AP_REQUEST,
                    self._nextSeq(),
                    self.conversationId,
                    authSchemes[0],
                    optimisticToken,
                )
            )

        self._messageHistory.extend(tokenParts)
        return b''.join(tokenParts)

    def createInitialResponse(self, contextToken=None):
        """First message from acceptor in response to initiator's token. This method produces:
        ACCEPTOR_NEGO + (optional) ACCEPTOR_META_DATA messages + (optional) MESSAGE_TYPE_CHALLENGE as in
        MS-NEGOEX 1.3.1.1
        """
        if self.isInitiator:
            raise NegoExError('createInitialResponse() is for the acceptor only')

        authSchemes = []
        metadataParts = []

        for schemeId in list(self._mutualSchemes):
            scheme = self._authSchemes.get(schemeId)
            if scheme is None:
                continue

            try:
                metadata = scheme.queryMetaData(False)
            except NegoExError as e:
                LOG.debug('NEGOEX: acceptor queryMetaData failed for %s: %s' % (schemeId, e))
                continue

            authSchemes.append(schemeId)
            if metadata:
                metadataParts.append((schemeId, metadata))

        self._mutualSchemes = authSchemes
        if self.selectedScheme not in self._mutualSchemes:
            self.selectedScheme = None
        if self._mutualSchemes and self.selectedScheme is None:
            self._selectMechanism()

        tokenParts = [createNegoMessage(MESSAGE_TYPE.ACCEPTOR_NEGO, self._nextSeq(), self.conversationId, authSchemes)]

        for schemeId, metadata in metadataParts:
            tokenParts.append(
                createExchangeMessage(
                    MESSAGE_TYPE.ACCEPTOR_META_DATA,
                    self._nextSeq(),
                    self.conversationId,
                    schemeId,
                    metadata,
                )
            )

        if contextToken and self.selectedScheme:
            tokenParts.append(
                createExchangeMessage(
                    MESSAGE_TYPE.CHALLENGE,
                    self._nextSeq(),
                    self.conversationId,
                    self.selectedScheme,
                    contextToken,
                )
            )

        self._messageHistory.extend(tokenParts)
        return b''.join(tokenParts)

    def createContextToken(self, exchangeData, includeVerify=False):
        #this builds the EXCHANGE_MESSAGE for non-initial turns during the negoex exchange.
        if self.selectedScheme is None:
            raise NegoExError('No NEGOEX mechanism selected')

        msgType = MESSAGE_TYPE.AP_REQUEST if self.isInitiator else MESSAGE_TYPE.CHALLENGE
        tokenParts = []

        if exchangeData:
            exchangeBytes = createExchangeMessage(
                msgType,
                self._nextSeq(),
                self.conversationId,
                self.selectedScheme,
                exchangeData,
            )
            tokenParts.append(exchangeBytes)
            self._messageHistory.append(exchangeBytes)

        if includeVerify:
            verifyBytes = self._createVerify()
            if verifyBytes:
                tokenParts.append(verifyBytes)
                # _createVerify computes its checksum from
                # _messageHistory BEFORE the VERIFY is appended, so we
                # only append after the checksum is sealed.
                self._messageHistory.append(verifyBytes)

        return b''.join(tokenParts)


    def processToken(self, tokenData):
        messages = parseNegoExToken(tokenData)
        result = {'context_token': None, 'auth_scheme': None, 'alerts': []}

        for pm in messages:
            if pm.message is None:
                raise NegoExParseError('Unsupported NEGOEX MessageType: %r' % pm.message_type, offset=pm.offset)

            # Drive sequence-number tracking from the parsed header.
            seq = pm.message['Header']['SequenceNum']
            if seq >= self._seqNum:
                self._seqNum = seq + 1

            if pm.message_type in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
                self._processNego(pm.message)
            elif pm.message_type in (MESSAGE_TYPE.INITIATOR_META_DATA, MESSAGE_TYPE.ACCEPTOR_META_DATA):
                self._processMetadata(pm.message)
            elif pm.message_type == MESSAGE_TYPE.VERIFY:
                # Smth Important: validate the VERIFY checksum before this
                # message is appended to _messageHistory, otherwise the
                # checksum input would include the VERIFY itself.
                self._processVerify(pm.message)
            elif pm.message_type in (MESSAGE_TYPE.AP_REQUEST, MESSAGE_TYPE.CHALLENGE):
                if self.selectedScheme is None and self._mutualSchemes:
                    self._selectMechanism()
                result['context_token'] = pm.message['Exchange']
                result['auth_scheme'] = _normalizeGuid(pm.message['AuthScheme'])
            elif pm.message_type == MESSAGE_TYPE.ALERT:
                result['alerts'].append(pm.message)

            # Append AFTER processing so VERIFY validation sees the right
            # history. For non-VERIFY messages the order doesn't matter
            # I believe, but doing it uniformly keeps things simple:
            # when checksumming, _messageHistory contains every
            # message already exchanged, in wire order.
            self._messageHistory.append(pm.raw_data)

        if self.selectedScheme is None and self._mutualSchemes:
            self._selectMechanism()

        return result


    # State helpers

    def _processNego(self, negoMsg):
        if not self.isInitiator:
            self.conversationId = negoMsg['Header']['ConversationId']
        elif self.conversationId is not None:
            expected = _normalizeGuid(self.conversationId)
            actual = _normalizeGuid(negoMsg['Header']['ConversationId'])
            if expected != actual:
                raise NegoExError('NEGOEX ConversationId mismatch: expected %s, got %s' % (expected, actual))
            
        for extension in negoMsg.getExtensionList():
            if extension.isCritical():
                raise NegoExError('Unknown critical NEGOEX extension: 0x%08x' % extension['ExtensionType'])

        peer = negoMsg.getAuthSchemeList()
        localOrder = self._authSchemeOrder
        mutual = set(peer).intersection(localOrder)

        # [MS-NEGOEX] 3.1.5.5.2 is as follows:
        #   - When we are the INITIATOR processing the acceptor's NEGO,
        #     iterate in the peer (acceptor) order.
        #   - When we are the ACCEPTOR processing the initiator's NEGO,
        #     iterate in our own (acceptor's) local order.
        ordered = peer if self.isInitiator else localOrder

        self._mutualSchemes = [scheme for scheme in ordered if scheme in mutual]

        if self.selectedScheme is not None and self.selectedScheme not in self._mutualSchemes:
            self.selectedScheme = None

    def _processMetadata(self, exchangeMsg):
        schemeId = uuid.UUID(bytes_le=exchangeMsg['AuthScheme'])
        scheme = self._authSchemes.get(schemeId)
        if scheme is None:
            LOG.debug('NEGOEX: ignoring metadata for unsupported scheme %s' % schemeId)
            return

        try:
            accepted = scheme.exchangeMetaData(self.isInitiator, exchangeMsg['Exchange'])
        except NegoExError as e:
            LOG.debug('NEGOEX: exchangeMetaData failed for %s: %s' % (schemeId, e))
            accepted = False

        if not accepted and schemeId in self._mutualSchemes:
            self._mutualSchemes.remove(schemeId)
            if self.selectedScheme == schemeId:
                self.selectedScheme = None

    def _processVerify(self, verifyMsg):
        self._verifyReceived = True
        schemeId = uuid.UUID(bytes_le=verifyMsg['AuthScheme'])
        scheme = self._authSchemes.get(schemeId)
        if scheme is None:
            raise NegoExError('NEGOEX VERIFY from unknown scheme %s' % schemeId)

        keyInfo = scheme.getVerifyKey()
        if keyInfo is None:
            LOG.warning('NEGOEX: received VERIFY but mechanism has no key material')
            return

        keyBytes, enctype, checksumType = keyInfo
        keyUsage = NEGOEX_KEYUSAGE_ACCEPTOR if self.isInitiator else NEGOEX_KEYUSAGE_INITIATOR

        # draft-zhu-negoex-04 §7.7 / [MS-NEGOEX] 2.2.6.5: the checksum
        # covers all messages exchanged before this VERIFY. _messageHistory
        # at this point holds those messages: the caller in
        # processToken appends pm.raw_data only AFTER returning from us.
        checksumInput = b''.join(self._messageHistory)
        expected = make_checksum(checksumType, Key(enctype, keyBytes), keyUsage, checksumInput)

        if expected != verifyMsg['ChecksumValue']:
            raise NegoExChecksumError(expected, verifyMsg['ChecksumValue'])

        LOG.debug('NEGOEX: VERIFY checksum valid for scheme %s' % schemeId)

    def _selectMechanism(self):
        if self.selectedScheme in self._mutualSchemes:
            return
        self.selectedScheme = None
        if not self._mutualSchemes:
            raise NegoExError('No mutually-supported NEGOEX authentication schemes')
        self.selectedScheme = self._mutualSchemes[0]
        LOG.debug('NEGOEX: selected mechanism %s' % self.selectedScheme)

    def _createVerify(self):
        if self._verifySent or self.selectedScheme is None:
            return None

        scheme = self._authSchemes.get(self.selectedScheme)
        if scheme is None:
            return None

        keyInfo = scheme.getVerifyKey()
        if keyInfo is None:
            return None

        keyBytes, enctype, checksumType = keyInfo
        keyUsage = NEGOEX_KEYUSAGE_INITIATOR if self.isInitiator else NEGOEX_KEYUSAGE_ACCEPTOR

        # Snapshot the history BEFORE producing the VERIFY. The caller
        # (createContextToken) is responsible for appending the resulting
        # bytes to _messageHistory, after this function returns.
        checksumInput = b''.join(self._messageHistory)
        checksum = make_checksum(checksumType, Key(enctype, keyBytes), keyUsage, checksumInput)
        verify = createVerifyMessage(
            self._nextSeq(),
            self.conversationId,
            self.selectedScheme,
            checksum,
            checksumType,
        )
        self._verifySent = True
        return verify

    def _nextSeq(self):
        seq = self._seqNum
        self._seqNum += 1
        return seq
    

class NegoExError(Exception):
    pass


class NegoExParseError(NegoExError):
    def __init__(self, message, offset=None, field=None):
        self.offset = offset
        self.field = field
        parts = [message]
        if field is not None:
            parts.append('field=%s' % field)
        if offset is not None:
            parts.append('offset=0x%x' % offset)
        Exception.__init__(self, ' | '.join(parts))


class NegoExChecksumError(NegoExError):
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        NegoExError.__init__(
            self,
            'NEGOEX VERIFY checksum mismatch: expected %s, got %s' % (expected.hex(), actual.hex()),
        )
