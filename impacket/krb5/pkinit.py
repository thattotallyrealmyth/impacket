# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "impacket>=0.13.1",
# ]
# ///

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
#   PKINIT (RFC 4556) support for Kerberos authentication. Provides
#   certificate-based initial authentication using Diffie-Hellman key
#   exchange and CMS/PKCS#7 signed data.
#
#   The Diffie-Hellman exchange, the reply-key derivation and the overall
#   message flow are derived from skelsec's minikerberos PKINIT
#   implementation. Pretty much hes the reason why this even 
#
# References:
#   RFC 4556 - Public Key Cryptography for Initial Authentication in
#              Kerberos (PKINIT)
#   RFC 4120 - The Kerberos Network Authentication Service (V5)
#   RFC 3526 - MODP Diffie-Hellman groups for IKE (Group 14)
#   RFC 5652 - Cryptographic Message Syntax (CMS)
#   [MS-PKCA] - Windows PKINIT implementation specifics
#
# Author:
#   Abdul Mhanni
#

import datetime
import hashlib
import os
import random

from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1_modules import rfc5280, rfc5652

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, AS_REP, EncASRepPart, KerberosTime, Int32, \
    KERB_PA_PAC_REQUEST, seq_set, seq_set_iter, _sequence_component, \
    _sequence_optional_component
from impacket.krb5.types import Principal, KerberosTime as KerberosTimeHelper
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import sendReceive
from impacket import LOG

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12


# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random


# PKINIT OIDs (RFC 4556 Section 3.2)
id_pkinit_authData = '1.3.6.1.5.2.3.1'
id_pkinit_DHKeyData = '1.3.6.1.5.2.3.2'

# Diffie-Hellman OID (RFC 2631 / RFC 3279)
id_dhpublicnumber = '1.2.840.10046.2.1'

# CMS / signature OIDs
id_signedData = '1.2.840.113549.1.7.2'
id_sha1 = '1.3.14.3.2.26'
id_rsaEncryption = '1.2.840.113549.1.1.1'
id_sha1WithRSAEncryption = '1.2.840.113549.1.1.5'
id_ecdsaWithSHA256 = '1.2.840.10045.4.3.2'

# CMS attribute OIDs (RFC 5652 Section 11)
id_contentType = '1.2.840.113549.1.9.3'
id_messageDigest = '1.2.840.113549.1.9.4'


################################################################################
# PKINIT ASN.1 types (RFC 4556 Appendix A)
################################################################################

def _sequence_implicit_component(name, tag_value, asn1_object, **subkwargs):
    # Like _sequence_component but uses IMPLICIT tagging, which several PKINIT
    # fields require per RFC 4556 Appendix A.
    return namedtype.NamedType(name, asn1_object.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_value),
        **subkwargs
    ))


def _sequence_optional_implicit_component(name, tag_value, asn1_object, **subkwargs):
    return namedtype.OptionalNamedType(name, asn1_object.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, tag_value),
        **subkwargs
    ))


class PKAuthenticator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('cusec', 0, Int32()),
        _sequence_component('ctime', 1, KerberosTime()),
        _sequence_component('nonce', 2, Int32()),
        _sequence_optional_component('paChecksum', 3, univ.OctetString()),
    )


class AuthPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('pkAuthenticator', 0, PKAuthenticator()),
        _sequence_optional_component('clientPublicValue', 1, rfc5280.SubjectPublicKeyInfo()),
        _sequence_optional_component(
            'supportedCMSTypes',
            2,
            univ.SequenceOf(componentType=rfc5280.AlgorithmIdentifier())
        ),
        _sequence_optional_component('clientDHNonce', 3, univ.OctetString()),
    )


class ExternalPrincipalIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_implicit_component('subjectName', 0, univ.OctetString()),
        _sequence_optional_implicit_component('issuerAndSerialNumber', 1, univ.OctetString()),
        _sequence_optional_implicit_component('subjectKeyIdentifier', 2, univ.OctetString()),
    )


class PA_PK_AS_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_implicit_component('signedAuthPack', 0, univ.OctetString()),
        _sequence_optional_component(
            'trustedCertifiers',
            1,
            univ.SequenceOf(componentType=ExternalPrincipalIdentifier())
        ),
        _sequence_optional_implicit_component('kdcPkId', 2, univ.OctetString()),
    )


class DHRepInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_implicit_component('dhSignedData', 0, univ.OctetString()),
        _sequence_optional_component('serverDHNonce', 1, univ.OctetString()),
    )


class PA_PK_AS_REP(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'dhInfo',
            DHRepInfo().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType(
            'encKeyPack',
            univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
    )


class KDCDHKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('subjectPublicKey', 0, univ.BitString()),
        _sequence_component('nonce', 1, Int32()),
        _sequence_optional_component('dhKeyExpiration', 2, KerberosTime()),
    )


# DomainParameters RFC 3279 Section 2.3.3
class DHDomainParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('p', univ.Integer()),
        namedtype.NamedType('g', univ.Integer()),
        namedtype.NamedType('q', univ.Integer()),
    )


################################################################################
# Diffie-Hellman key exchange
################################################################################

# Oakley Group 14 (2048-bit MODP) from RFC 3526 Section 3
DH_P = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
    16
)

DH_G = 2


class DiffieHellman:
    def __init__(self, p=None, g=None):
        self.p = p if p is not None else DH_P
        self.g = g if g is not None else DH_G
        self.privateKey = int(os.urandom(32).hex(), 16)
        self.dhNonce = os.urandom(32)

    def getPublicKey(self):
        return pow(self.g, self.privateKey, self.p)

    def exchange(self, otherPublicKey):
        sharedInt = pow(otherPublicKey, self.privateKey, self.p)
        hexStr = '%x' % sharedInt
        if len(hexStr) % 2 != 0:
            hexStr = '0' + hexStr
        return bytes.fromhex(hexStr)


################################################################################
# Reply-key derivation RFC 4556 Section 3.2.3.1
################################################################################

def truncateKey(value, keySize):
    output = b''
    currentNum = 0

    while len(output) < keySize:
        currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()

        if len(output) + len(currentDigest) > keySize:
            output += currentDigest[:keySize - len(output)]
            break

        output += currentDigest
        currentNum += 1

    return output


################################################################################
# DER helper for PKINIT paChecksum
################################################################################

def _readDERLength(data, offset):
    if offset >= len(data):
        raise Exception('Invalid DER length: offset beyond data')

    first = data[offset]
    offset += 1

    if first & 0x80 == 0:
        return first, offset

    lengthBytes = first & 0x7f

    if lengthBytes == 0:
        raise Exception('Invalid DER length: indefinite form is not valid in DER')

    if offset + lengthBytes > len(data):
        raise Exception('Invalid DER length: truncated length field')

    length = int.from_bytes(data[offset:offset + lengthBytes], 'big')
    offset += lengthBytes

    return length, offset


def _unwrapExplicitContextTag(derData, expectedTag):
    """
    seq_set(asReq, 'req-body') gives us the req-body component with the outer
    Kerberos context-specific EXPLICIT [4] tag.

    PKINIT paChecksum is SHA1(DER(KDC-REQ-BODY))
    """
    if not derData:
        return derData

    if derData[0] != expectedTag:
        return derData

    length, valueOffset = _readDERLength(derData, 1)
    valueEnd = valueOffset + length

    if valueEnd > len(derData):
        raise Exception('Invalid DER length: value exceeds data size')

    return derData[valueOffset:valueEnd]


def encodeKDCReqBodyForPKINITChecksum(reqBody):
    reqBodyDER = encoder.encode(reqBody)

    # Kerberos req-body field is [4] EXPLICIT, DER tag 0xa4.
    # Strip that wrapper if present.
    return _unwrapExplicitContextTag(reqBodyDER, 0xa4)


################################################################################
# CMS SignedData (RFC 5652)
################################################################################

def signAuthPack(authPackDER, certificate, privateKey):
    # Builds the CMS ContentInfo (id-signedData) carrying the signed AuthPack,
    # as expected by the KDC (RFC 4556 Section 3.2.1).
    contentDigest = hashlib.sha1(authPackDER).digest()

    # signedAttrs is content-type + message-digest (RFC 5652 Section 5.3)
    contentTypeAttr = rfc5652.Attribute()
    contentTypeAttr['attrType'] = id_contentType
    contentTypeAttr['attrValues'][0] = univ.Any(
        encoder.encode(univ.ObjectIdentifier(id_pkinit_authData))
    )

    messageDigestAttr = rfc5652.Attribute()
    messageDigestAttr['attrType'] = id_messageDigest
    messageDigestAttr['attrValues'][0] = univ.Any(
        encoder.encode(univ.OctetString(contentDigest))
    )

    # Embedded in SignerInfo the attributes carry an IMPLICIT [0] tag.
    signedAttrs = rfc5652.SignedAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    signedAttrs[0] = contentTypeAttr
    signedAttrs[1] = messageDigestAttr

    # For the signature the attributes are DER-encoded with a universal SET OF
    # tag rather than the IMPLICIT [0] tag (RFC 5652 Section 5.4).
    signedAttrsDER = b'\x31' + encoder.encode(signedAttrs)[1:]

    if isinstance(privateKey, rsa.RSAPrivateKey):
        signature = privateKey.sign(
            signedAttrsDER,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

        # SignerInfo.signatureAlgorithm is
        # rsaEncryption and digestAlgorithm separately carries SHA-1.
        signatureOID = id_rsaEncryption

    elif isinstance(privateKey, ec.EllipticCurvePrivateKey):
        signature = privateKey.sign(
            signedAttrsDER,
            ec.ECDSA(hashes.SHA256())
        )
        signatureOID = id_ecdsaWithSHA256

    else:
        raise Exception('Unsupported private key type for PKINIT signing')

    issuer = decoder.decode(
        certificate.issuer.public_bytes(),
        asn1Spec=rfc5280.Name()
    )[0]

    issuerAndSerial = rfc5652.IssuerAndSerialNumber()
    issuerAndSerial['issuer'] = issuer
    issuerAndSerial['serialNumber'] = certificate.serial_number

    sid = rfc5652.SignerIdentifier()
    sid['issuerAndSerialNumber'] = issuerAndSerial

    digestAlgorithm = rfc5280.AlgorithmIdentifier()
    digestAlgorithm['algorithm'] = id_sha1

    signatureAlgorithm = rfc5280.AlgorithmIdentifier()
    signatureAlgorithm['algorithm'] = signatureOID

    if signatureOID == id_rsaEncryption:
        signatureAlgorithm['parameters'] = univ.Any(
            encoder.encode(univ.Null(''))
        )

    signerInfo = rfc5652.SignerInfo()
    signerInfo['version'] = 1
    signerInfo['sid'] = sid
    signerInfo['digestAlgorithm'] = digestAlgorithm
    signerInfo['signedAttrs'] = signedAttrs
    signerInfo['signatureAlgorithm'] = signatureAlgorithm
    signerInfo['signature'] = signature

    encapContentInfo = rfc5652.EncapsulatedContentInfo()
    encapContentInfo['eContentType'] = id_pkinit_authData
    encapContentInfo['eContent'] = authPackDER

    certificateASN1 = decoder.decode(
        certificate.public_bytes(serialization.Encoding.DER),
        asn1Spec=rfc5280.Certificate()
    )[0]

    certChoice = rfc5652.CertificateChoices()
    certChoice['certificate'] = certificateASN1

    digestAlgorithms = rfc5280.AlgorithmIdentifier()
    digestAlgorithms['algorithm'] = id_sha1

    signedData = rfc5652.SignedData()
    signedData['version'] = 3
    signedData['digestAlgorithms'][0] = digestAlgorithms
    signedData['encapContentInfo'] = encapContentInfo
    signedData['certificates'][0] = certChoice
    signedData['signerInfos'][0] = signerInfo

    # Wrap the SignedData in a CMS ContentInfo (RFC 4556 Section 3.2.1)
    contentInfo = rfc5652.ContentInfo()
    contentInfo['contentType'] = id_signedData
    contentInfo['content'] = univ.Any(encoder.encode(signedData))

    return encoder.encode(contentInfo)


def extractSignedContent(contentInfoDER):
    # Returns the (eContent, eContentType) carried by a CMS ContentInfo
    # wrapping a SignedData.
    contentInfo = decoder.decode(
        contentInfoDER,
        asn1Spec=rfc5652.ContentInfo()
    )[0]

    signedData = decoder.decode(
        contentInfo['content'],
        asn1Spec=rfc5652.SignedData()
    )[0]

    encapContentInfo = signedData['encapContentInfo']
    eContent = bytes(encapContentInfo['eContent'])
    eContentType = str(encapContentInfo['eContentType'])

    return eContent, eContentType


def buildPaPkAsReq(signedAuthPack):
    paReq = PA_PK_AS_REQ()
    paReq['signedAuthPack'] = signedAuthPack
    return encoder.encode(paReq)


################################################################################
# Certificate loading
################################################################################

def loadCertAndKeyFromPFX(pfxFile, password=None):
    if password == '':
        password = None

    if isinstance(password, str):
        password = password.encode()

    with open(pfxFile, 'rb') as f:
        privateKey, certificate, _ = pkcs12.load_key_and_certificates(
            f.read(),
            password
        )

    return privateKey, certificate


def loadCertAndKeyFromPEM(certFile, keyFile):
    with open(certFile, 'rb') as f:
        certificate = x509.load_pem_x509_certificate(f.read())

    with open(keyFile, 'rb') as f:
        privateKey = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    return privateKey, certificate


################################################################################
# AuthPack construction
################################################################################

def _buildAuthPack(diffie, pkAuthNonce, reqBodyDER, now):
    # if caller accidentally passed,  strip it before calculating paChecksum.
    reqBodyDER = _unwrapExplicitContextTag(reqBodyDER, 0xa4)

    dhParameters = DHDomainParameters()
    dhParameters['p'] = diffie.p
    dhParameters['g'] = diffie.g
    dhParameters['q'] = 0

    publicValueDER = encoder.encode(univ.Integer(diffie.getPublicKey()))

    authPack = AuthPack()

    # paChecksum is the SHA-1 of the DER-encoded bare KDC-REQ-BODY.
    authPack['pkAuthenticator'] = noValue
    authPack['pkAuthenticator']['cusec'] = now.microsecond
    authPack['pkAuthenticator']['ctime'] = KerberosTimeHelper.to_asn1(now)
    authPack['pkAuthenticator']['nonce'] = pkAuthNonce
    authPack['pkAuthenticator']['paChecksum'] = hashlib.sha1(reqBodyDER).digest()

    authPack['clientPublicValue'] = noValue
    authPack['clientPublicValue']['algorithm'] = noValue
    authPack['clientPublicValue']['algorithm']['algorithm'] = id_dhpublicnumber
    authPack['clientPublicValue']['algorithm']['parameters'] = univ.Any(
        encoder.encode(dhParameters)
    )
    authPack['clientPublicValue']['subjectPublicKey'] = univ.BitString(
        hexValue=publicValueDER.hex()
    )

    authPack['clientDHNonce'] = diffie.dhNonce

    return encoder.encode(authPack)


################################################################################
# TGT acquisition
################################################################################

def getKerberosTGTPKINIT(clientName, certificate, privateKey, domain, kdcHost=None,
                         requestPAC=True, dhParams=None):
    # Requests a TGT using PKINIT (certificate-based authentication).
    if isinstance(clientName, str):
        clientName = Principal(
            clientName,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

    domain = domain.upper()

    serverName = Principal(
        'krbtgt/%s' % domain,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    diffie = dhParams if dhParams is not None else DiffieHellman()

    now = datetime.datetime.now(datetime.timezone.utc)

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    reqBody = seq_set(asReq, 'req-body')

    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ]

    reqBody['kdc-options'] = constants.encodeFlags(opts)

    seq_set(reqBody, 'cname', clientName.components_to_asn1)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)

    reqBody['realm'] = domain

    tillTime = now + datetime.timedelta(days=1)

    reqBody['till'] = KerberosTimeHelper.to_asn1(tillTime)
    reqBody['rtime'] = KerberosTimeHelper.to_asn1(tillTime)
    reqBody['nonce'] = rand.getrandbits(31)

    seq_set_iter(reqBody, 'etype', (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ))

    pkAuthNonce = rand.getrandbits(31)

    # checksum must be over DER(KDC-REQ-BODY), without the outer [4] EXPLICIT
    # tag used by the surrounding AS-REQ req-body field.
    reqBodyDER = encodeKDCReqBodyForPKINITChecksum(reqBody)

    authPackDER = _buildAuthPack(
        diffie,
        pkAuthNonce,
        reqBodyDER,
        now
    )

    signedAuthPack = signAuthPack(
        authPackDER,
        certificate,
        privateKey
    )

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = requestPAC

    asReq['padata'] = noValue

    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(
        constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value
    )
    asReq['padata'][0]['padata-value'] = buildPaPkAsReq(signedAuthPack)

    asReq['padata'][1] = noValue
    asReq['padata'][1]['padata-type'] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
    )
    asReq['padata'][1]['padata-value'] = encoder.encode(pacRequest)

    LOG.debug('Sending PKINIT AS-REQ to KDC %s' % (kdcHost or domain))

    tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)

    asRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

    return _processPKINITASRep(tgt, asRep, diffie, pkAuthNonce)


def _processPKINITASRep(tgt, asRep, diffie, expectedNonce):
    # Decrypts a PKINIT AS-REP and returns the same 4-tuple as getKerberosTGT
    paPkAsRepDER = None

    for padata in asRep['padata']:
        if int(padata['padata-type']) == int(
            constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value
        ):
            paPkAsRepDER = bytes(padata['padata-value'])
            break

    if paPkAsRepDER is None:
        raise Exception('PA-PK-AS-REP not found in AS-REP padata')

    paPkAsRep = decoder.decode(paPkAsRepDER, asn1Spec=PA_PK_AS_REP())[0]

    dhInfo = paPkAsRep['dhInfo']

    serverDHNonce = None
    if dhInfo['serverDHNonce'].hasValue():
        serverDHNonce = bytes(dhInfo['serverDHNonce'])

    content, contentType = extractSignedContent(
        bytes(dhInfo['dhSignedData'])
    )

    if contentType != id_pkinit_DHKeyData:
        LOG.warning('Unexpected content type in DHRepInfo: %s' % contentType)

    kdcDHKeyInfo = decoder.decode(content, asn1Spec=KDCDHKeyInfo())[0]

    if int(kdcDHKeyInfo['nonce']) != expectedNonce:
        raise Exception(
            'PKINIT nonce mismatch: expected %d, got %d' % (
                expectedNonce,
                int(kdcDHKeyInfo['nonce'])
            )
        )

    serverPublicKeyDER = kdcDHKeyInfo['subjectPublicKey'].asOctets()
    serverPublicKey = int(decoder.decode(serverPublicKeyDER, asn1Spec=univ.Integer())[0])

    sharedKey = diffie.exchange(serverPublicKey)

    if serverDHNonce is not None:
        fullKey = sharedKey + diffie.dhNonce + serverDHNonce
    else:
        fullKey = sharedKey

    enctype = int(asRep['enc-part']['etype'])
    cipher = _enctype_table[enctype]

    if enctype == int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):
        replyKey = Key(cipher.enctype, truncateKey(fullKey, 32))

    elif enctype == int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value):
        replyKey = Key(cipher.enctype, truncateKey(fullKey, 16))
    else:
        raise Exception('Unsupported enctype %d for PKINIT key derivation' % enctype)

    # Decrypt the AS-REP enc-part (RFC 4120 Section 7.5.1, key usage 3)
    plainText = cipher.decrypt(replyKey, 3, bytes(asRep['enc-part']['cipher']))

    encASRepPart = decoder.decode(plainText, asn1Spec=EncASRepPart())[0]
    sessionCipher = _enctype_table[int(encASRepPart['key']['keytype'])]
    sessionKey = Key(sessionCipher.enctype, bytes(encASRepPart['key']['keyvalue']))
    
    return tgt, sessionCipher, replyKey, sessionKey
