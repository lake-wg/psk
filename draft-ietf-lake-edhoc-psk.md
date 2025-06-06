---
title: "EDHOC Authenticated with Pre-Shared Keys (PSK)"
docname: draft-ietf-lake-edhoc-psk-latest
category: std

v3xml2rfc:
  silence:
  - Found SVG with width or height specified

submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
consensus: true
v: 3
area: Security
workgroup: LAKE Working Group
cat: std
venue:
  group: LAKE
  type: Working Group
  mail: lake@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/lake/
  github: lake-wg/psk
  latest: https://lake-wg.github.io/psk/#go.draft-ietf-lake-edhoc-psk.html

author:
 -
    name: Elsa Lopez-Perez
    organization: Inria
    email: elsa.lopez-perez@inria.fr
 -
    name: Göran Selander
    organization: Ericsson
    email: goran.selander@ericsson.com
 -
    name: John | Preuß Mattsson
    organization: Ericsson
    email: john.mattsson@ericsson.com
 -
    name: Rafael Marin-Lopez
    organization: University of Murcia
    email: rafa@um.es

normative:

  RFC9528:
  RFC9052:
  RFC9053:
  RFC8742:
  RFC8949:
  RFC8610:
  RFC8392:
  SP-800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A Revision 3"
    author:
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: A. Roginsky
      -
        ins: A. Vassilev
      -
        ins: R. Davis
    date: April 2018

informative:

--- abstract

This document specifies a Pre-Shared Key (PSK) authentication method for the Ephemeral Diffie-Hellman Over COSE (EDHOC) key exchange protocol. The PSK method enhances computational efficiency while providing mutual authentication, ephemeral key exchange, identity protection, and quantum resistance. It is particularly suited for systems where nodes share a PSK provided out-of-band (external PSK) and enables efficient session resumption with less computational overhead when the PSK is provided from a previous EDHOC session (resumption PSK). This document details the PSK method flow, key derivation changes, message formatting, processing, and security considerations.

--- middle

# Introduction

This document defines a Pre-Shared Key (PSK) authentication method for the Ephemeral Diffie-Hellman Over COSE (EDHOC) key exchange protocol {{RFC9528}}. The PSK method balances the complexity of credential distribution with computational efficiency. While symmetrical key distribution is more complex than asymmetrical approaches, PSK authentication offers greater computational efficiency compared to the methods outlined in {{RFC9528}}. The PSK method retains mutual authentication, asymmetric ephemeral key exchange, and identity protection established by {{RFC9528}}.

EDHOC with PSK authentication benefits use cases where two nodes share a Pre-Shared Key (PSK) provided out-of-band (external PSK). This applies to scenarios like the Authenticated Key Management Architecture (AKMA) in mobile systems or the Peer and Authenticator in Extensible Authentication Protocol (EAP) systems. The PSK method enables the nodes to perform ephemeral key exchange, achieving Perfect Forward Secrecy (PFS). This ensures that even if the PSK is compromised, past communications remain secure against active attackers, while future communications are protected from passive attackers. Additionally, by leveraging the PSK for both authentication and key derivation, the method offers quantum resistance key exchange and authentication.

Another key use case of PSK authentication in the EDHOC protocol is session resumption. This enables previously connected parties to quickly reestablish secure communication using pre-shared keys from a prior session, reducing the overhead associated with key exchange and asymmetric authentication. By using PSK authentication, EDHOC allows session keys to be refreshed with significantly lower computational overhead compared to public-key authentication. In this case, the PSK (resumption PSK) is provisioned after the establishment of a previous EDHOC session by using EDHOC_Exporter (resumption PSK).

Therefore, the external PSK is supposed to be a long-term credential while the resumption PSK is a session key.

Section 3 provides an overview of the PSK method flow and credentials. Section 4 outlines the changes to key derivation compared to {{RFC9528}}, Section 5 details message formatting and processing, and Section 6 discusses security considerations. How to derive keys for resumption is described in Section 7.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts described in EDHOC {{RFC9528}}, CBOR {{RFC8949}}, CBOR Sequences {{RFC8742}}, COSE Structures and Processing {{RFC9052}}, COSE Algorithms {{RFC9053}}, CWT and CCS {{RFC8392}}, and the Concise Data Definition Language (CDDL) {{RFC8610}}, which is used to express CBOR data structures.

# Protocol

In this method, the Pre-Shared Key identifier (ID_CRED_PSK) is sent in message_3. The ID_CRED_PSK allows retrieval of CRED_PSK, a COSE_Key compatible authentication credential that contains the external or resumption PSK. Through this document we will refer to the Pre-Shared Key authentication method as EDHOC-PSK.

## Credentials

Initiator and Responder are assumed to have a PSK (external PSK or resumption PSK) with good amount of randomness and the requirements that:

- Only the Initiator and the Responder have access to the PSK.
- The Responder is able to retrieve the PSK using ID_CRED_PSK.

where:

- ID_CRED_PSK is a COSE header map containing header parameters that can identify a pre-shared key. For example:

~~~~~~~~~~~~
ID_CRED_PSK = {4 : h'0f' }
~~~~~~~~~~~~

- CRED_PSK is a COSE_Key compatible authentication credential, i.e., a CBOR Web Token (CWT) or CWT Claims Set (CCS) {{RFC8392}} whose 'cnf' claim uses the confirmation method 'COSE_Key' encoding the PSK. For example:

~~~~~~~~~~~~
{                                               /CCS/
  2 : "mydotbot",                               /sub/
  8 : {                                         /cnf/
    1 : {                                       /COSE_Key/
       1 : 4,                                   /kty/
       2 : h'0f',                               /kid/
      -1 : h'50930FF462A77A3540CF546325DEA214'  /k/
    }
  }
}
~~~~~~~~~~~~

The purpose of ID_CRED_PSK is to facilitate the retrieval of the PSK.
It is RECOMMENDED that it uniquely identifies the CRED_PSK as the recipient might otherwise have to try several keys.
If ID_CRED_PSK contains a single 'kid' parameter, then the compact encoding is applied; see {{Section 3.5.3.2 of RFC9528}}.
The authentication credential CRED_PSK substitutes CRED_I and CRED_R specified in {{RFC9528}}, and, when applicable, MUST follow the same guidelines described in {{Section 3.5.2 and Section 3.5.3 of RFC9528}}.

## Message Flow of PSK

The ID_CRED_PSK is sent in message_3, encrypted using a key derived from the ephemeral shared secret, G_XY. The Responder authenticates the Initiator first.
{{fig-variant2}} shows the message flow of PSK authentication method.

~~~~~~~~~~~~ aasvg
Initiator                                                   Responder
|                  METHOD, SUITES_I, G_X, C_I, EAD_1                |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                      G_Y, Enc( C_R, EAD_2 )                       |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                   Enc( ID_CRED_PSK, AEAD( EAD_3 ) )               |
+------------------------------------------------------------------>|
|                             message_3                             |
|                                                                   |
|                           AEAD( EAD_4 )                           |
|<------------------------------------------------------------------+
|                             message_4                             |
~~~~~~~~~~~~
{: #fig-variant2 title="Overview of Message Flow of PSK." artwork-align="center"}

This approach provides protection against passive attackers for both Initiator and Responder.
message_4 remains optional, but is needed to authenticate the Responder and achieve mutual authentication in EDHOC if not relaying on external applications, such as OSCORE. With this fourth message, the protocol achieves both explicit key confirmation and mutual authentication.

# Key Derivation {#key-der}

The pseudorandom keys (PRKs) used for PSK authentication method in EDHOC are derived using EDHOC_Extract, as done in {{RFC9528}}.

~~~~~~~~~~~~
PRK  = EDHOC_Extract( salt, IKM )
~~~~~~~~~~~~

where the salt and input keying material (IKM) are defined for each key.
The definition of EDHOC_Extract depends on the EDHOC hash algorithm selected in the cipher suite.

{{fig-variant2key}} lists the key derivations that differ from those specified in {{Section 4.1.2 of RFC9528}}.

~~~~~~~~~~~~
PRK_3e2m    = PRK_2e
PRK_4e3m    = EDHOC_Extract( SALT_4e3m, CRED_PSK )
KEYSTREAM_3 = EDHOC_KDF( PRK_3e2m, 11, TH_3, plaintext_length_3 )
K_3         = EDHOC_KDF( PRK_4e3m, 3, TH_3, key_length )
IV_3        = EDHOC_KDF( PRK_4e3m, 4, TH_3, iv_length )
~~~~~~~~~~~~
{: #fig-variant2key title="Key Derivation of EDHOC PSK Authentication Method." artwork-align="center"}

where:

- KEYSTREAM_3 is used to encrypt the ID_CRED_PSK in message_3.
- TH_3 = H( TH_2, PLAINTEXT_2 )

Additionally, the definition of the transcript hash TH_4 is modified as:

- TH_4 = H( TH_3, ID_CRED_PSK, ? EAD_3, CRED_PSK )

# Message Formatting and Processing

This section specifies the differences in message formatting and processing compared to {{Section 5 of RFC9528}}.

## Message 1

Message 1 is formatted and processed as specified in {{Section 5.2 of RFC9528}}.

## Message 2

### Formatting of Message 2

Message 2 is formatted as specified in {{Section 5.3.1 of RFC9528}}.

### Responder Composition of Message 2

CIPHERTEXT_2 is calculated with a binary additive stream cipher, using a keystream generated with EDHOC_Expand, and the following plaintext:

* PLAINTEXT_2B = ( C_R, ? EAD_2 )
* CIPHERTEXT_2 = PLAINTEXT_2B XOR KEYSTREAM_2

Contrary to {{RFC9528}}, ID_CRED_R, MAC_2, and Signature_or_MAC_2 are not used. C_R, EAD_2, and KEYSTREAM_2 are defined in {{Section 5.3.2 of RFC9528}}.

### Initiator Processing of Message 2

Compared to {{Section 5.3.3 of RFC9528}}, ID_CRED_R is not made available to the application in step 4, and steps 5 and 6 are skipped

## Message 3

### Formatting of Message 3

Message 3 is formatted as specified in {{Section 5.4.1 of RFC9528}}.

### Initiator Composition of Message 3

* CIPHERTEXT_3 is calculated with a binary additive stream cipher, using a keystream generated with EDHOC_Expand, and the following plaintext:

   * PLAINTEXT_3A = ( ID_CRED_PSK / bstr / -24..23, CIPHERTEXT_3B )

      * If ID_CRED_PSK contains a single 'kid' parameter, i.e., ID_CRED_PSK = { 4 : kid_PSK }, then the compact encoding is applied, see {{Section 3.5.3.2 of RFC9528}}.

      * If the length of PLAINTEXT_3A exceeds the output of EDHOC_KDF, then {{Appendix G of RFC9528}} applies.

   * Compute KEYSTREAM_3 as in {{key-der}}, where plaintext_length is the length of PLAINTEXT_3A.

   * CIPHERTEXT_3 = PLAINTEXT_3A XOR KEYSTREAM_3

* CIPHERTEXT_3B is the 'ciphertext' of COSE_Encrypt0 object as defined in {{Section 5.2 and Section 5.3 of RFC9528}}, with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_3, the initialization vector IV_3 (if used by the AEAD algorithm), the parameters described in {{Section 5.2 of RFC9528}}, plaintext PLAINTEXT_3B and the following parameters as input:

  - protected = h''
  - external_aad = << ID_CRED_PSK, TH_3, CRED_PSK >>
  - K_3 and IV_3 as defined in {{key-der}}
  - PLAINTEXT_3B = ( ? EAD_3 )

The Initiator computes TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_PSK ), defined in {{key-der}}.

### Responder Processing of Message 3

## Message 4

Message 4 is formatted and processed as specified in {{Section 5.5 of RFC9528}}.

Compared to {{RFC9528}}, a fourth message does not only provide key confirmation but also Responder authentication. To authenticate the Responder and achieve mutual authentication, a fourth message is mandatory.

After verifying message_4, the Initiator is assured that the Responder has calculated the key PRK_out (key confirmation) and that no other party can derive the key. The Initiator MUST NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message, from the Responder and the application has authenticated the Responder.

# Security Considerations

PSK authentication method introduces changes with respect to the current specification of EDHOC {{RFC9528}}. This section analyzes the security implications of these changes.

## Identity protection

EDHOC-PSK encrypts ID_CRED_PSK in message 3, XOR encrypted with a keystream derived from the ephemeral shared secret G_XY. As a consequence, contrary to the current EDHOC methods that protect the Initiator’s identity against active attackers and the Responder’s identity against passive attackers (See {{Section 9.1 of RFC9528}}), EDHOC-PSK provides identity protection for both the Initator and the Responder against passive attackers.

## Mutual Authentication

Authentication in EDHOC-PSK depends on the security of the session key and the protocol's confidentiality. Both security properties hold as long as the PSK remains secret. Even though the fourth message (message_4) remains optional, mutual authentication is not guaranteed without it, or without an OSCORE message or any application data that confirms that the Responder owns the PSK. When message_4 is included, the protocol achieves explicit key confirmation in addition to mutual authentication.

## External Authorization Data Protection

Similarly to {{RFC9528}}, EDHOC-PSK provides external authorization data protection. The integrity and confidentiality of EAD fields follow the same security guarantees as in the original EDHOC specification.

## Post Quantum Considerations

Recent achievements in developing quantum computers demonstrate that it is probably feasible to build one that is cryptographically significant. If such a computer is implemented, many of the cryptographic algorithms and protocols currently in use would be insecure. A quantum computer would be able to solve Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH) problems in polynomial time.

EDCHOC with pre-shared keys would not be vulnerable to quantum attacks because those keys are used as inputs to the key derivation function. The use of intermediate keys derived through key derivation functions ensure that the message is not immediately compromised if the symmetrically distributed key (PSK) is compromised, or if the algorithm used to distribute keys asymmetrically (DH) is broken. If the pre-shared key has sufficient entropy and the Key Derivation Function (KDF), encryption, and authentication transforms are quantum secure, then the resulting system is believed to be quantum secure.
Therefore, provided that the PSK remains secret, EDHOC-PSK provides confidentiality, mutual authentication and Perfect Forward Secrecy (PFS) even in the presence of quantum attacks. What is more, the key exchange is still a key agreement where both parties contribute with randomness.

## Independence of Session Keys

NIST mandates that an ephemeral private key shall be used in exactly one key-establishment transaction (see Section 5.6.3.3 of {{SP-800-56A}}). This requirement is essential for preserving session key independence and ensuring forward secrecy. The EDHOC-PSK protocol complies with this NIST requirement.

In other protocols, the reuse of ephemeral keys, particularly when combined with implementation flaws such as the absence of public key validation, has resulted in critical security vulnerabilities. Such weaknesses have allowed attackers to recover the so called “ephemeral” private key from a compromised session, thereby enabling them to compromise the security of both past and future sessions between legitimate parties. Assuming breach and minimizing the impact of compromise are fundamental zero-trust principles.

## Unified Approach and Recommendations

For use cases involving the transmission of application data, application data can be sent concurrently with message_3, maintaining the protocol's efficiency.
In applications such as EAP-EDHOC, where application data is not sent, message_4 is mandatory. Thus, EDHOC-PSK authentication method does not include any extra messages.
Other implementations may continue using OSCORE in place of EDHOC message_4, with a required change in the protocol's language to:
      The Initiator SHALL NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message.

This change ensures that key materials are only stored once their integrity and authenticity are confirmed, thereby enhancing privacy by preventing early storage of potentially compromised keys.

Lastly, whether the Initiator or Responder authenticates first is not relevant when using symmetric keys.
This consideration was important for the privacy properties when using asymmetric authentication but is not significant in the context of symmetric key usage.

# PSK usage for Session Resumtpion {#psk-resumption}

This section defines how PSKs are used for session resumption in EDHOC.
Following {{Section 4.2 of RFC9528}}, EDHOC_Exporter can be used to derive both CRED_PSK and ID_CRED_PSK:

~~~~~~~~~~~~
CRED_PSK = EDHOC_Exporter( 2, h'', resumption_psk_length )
ID_CRED_PSK = EDHOC_Exporter( 3, h'', id_cred_psk_length )
~~~~~~~~~~~~

where:

  - resumption_pks_length is by default, at least, the key_length (length of the encryption key of the EDHOC AEAD algorithm of the selected cipher suite) of the session in which the EDHOC_Exporter is called.
  - id_cred_psk_length is by default 2.

A peer that has successfully completed an EDHOC session, regardless of the used authentication method, MUST generate a resumption key to use for the next resumption in the present "session series", as long as it supports PSK resumption.
To guarantee that both peers share the same resumption key, when a session is run using rPSK_i as a resumption key
  - The Initiator can delete rPSK_i after having successfully verified EDHOC message_4.
    In this case, the Responder will have derived the next rPSK_(i+1), which the Initiator can know for sure, upon receiving EDHOC message_4.
  - The Responder can delete rPSK_(i-1), if any, after having successfully sent EDHOC message_4.
    That is, upon receiving EDHOC message_3, the Responder knows for sure that the other peer did derive rPSK_i at the end of the previous session in the "session series", thus making it safe to delete the previous resumption key rPSK_(i-1).


## Ciphersuite Requirements for Resumption

When using a resumption PSK derived from a previous EDHOC exchange:

  1. The resumption PSK MUST only be used with the same ciphersuite that was used in the original EDHOC exchange, or with a ciphersuite that provides equal or higher security guarantees.
  2. Implementations SHOULD manitain a mapping between the resumption PSK and its originating ciphersuite to enforce this requirement.
  3. If a resumption PSK is offered with a ciphersuite different from the one used in the original EDHOC session, the recipient can fail the present EDHOC session according to application-specific policies.

## Privacy Considerations for Resumption

When using resumption PSKs:

  - The same ID_CRED_PSK is reused each time EDHOC is executed with a specific resumption PSK.
  - To prevent long-term tracking, implementations SHOULD periodically initiate a full EDHOC exchange to generate a new resumption PSK and corresponding ID_CRED_PSK. Alternatively, as stated in {{Appendix H of RFC9528}}, EDHOC_KeyUpdate can be used to derive a new PRK_out, and consequently a new CRED_PSK and ID_CRED_PSK for session resumption.


## Security Considerations for Resumption

- Resumption PSKs MUST NOT be used for purposes other than EDHOC session resumption.
- Resumption PSKs MUST be securely stored with the same level of protection as the original session keys.
- Parties SHOULD implement mechanisms to detect and prevent excessive reuse of the same resumption PSK.

# IANA Considerations

This document has IANA actions.

## EDHOC Method Type Registry

IANA is requested to register the following entry in the "EDHOC Method Type" registry under the group name "Ephemeral Diffie-Hellman Over OCSE (EDHOC)".

~~~~~~~~~~~ aasvg
+------------+------------------------------+---------------------------------+-------------------+
| Value      | Initiator Authentication Key | Responder Authentication Key    | Reference         |
+============+==============================+=================================+===================+
|  4         |                 PSK          |                 PSK             |                   |
+------------+------------------------------+---------------------------------+-------------------+

~~~~~~~~~~~
{: #fig-method-psk title="Addition to the EDHOC Method Type Registry."}

## EDHOC Exporter Label Registry

IANA is requested to register the following entry in the "EDHOC Exporter Label" registry under the group name "Ephemeral Diffie-Hellman Over OCSE (EDHOC)".

~~~~~~~~~~~ aasvg
+------------+------------------------------+-------------------+-------------------+
| Label      | Descritpion                  | Change Controller | Reference         |
+============+==============================+===================+===================+
|  2         | Resumption CRED_PSK          |       IETF        | Section 7         |
+------------+------------------------------+-------------------+-------------------+
|  3         | Resumption ID_CRED_PSK       |       IETF        | Section 7         |
+------------+------------------------------+-------------------+-------------------+

~~~~~~~~~~~
{: #fig-exporter-psk title="Addition to the EDHOC Exporter Label Registry."}

## EDHOC Info Label Registry

IANA is requested to register the following registry "EDHOC Info Label" under the group name "Ephemeral Diffie-Hellman Over OCSE (EDHOC)".

~~~~~~~~~~~ aasvg
+------------+-----------------------+-------------------+
| Label      |          Key          |  Reference        |
+============+=======================+===================+
|  11        |       KEYSTREAM_3     |   Section 4       |
+------------+-----------------------+-------------------+

~~~~~~~~~~~
{: #fig-info-label-psk title="EDHOC Info Label Registry."}

--- back

# CDDL Definitions {#CDDL}

This section compiles the CDDL definitions for easy reference, incorporating errata filed against {{RFC9528}}.

~~~~~~~~~~~ CDDL
suites = [ 2* int ] / int

ead = (
  ead_label : int,
  ? ead_value : bstr,
)

EAD_1 = (1* ead)
EAD_2 = (1* ead)
EAD_3 = (1* ead)
EAD_4 = (1* ead)

message_1 = (
  METHOD : int,
  SUITES_I : suites,
  G_X : bstr,
  C_I : bstr / -24..23,
  ? EAD_1,
)

message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
)

PLAINTEXT_2B = (
  C_R : bstr / -24..23,
  ? EAD_2,
)

message_3 = (
  CIPHERTEXT_3 : bstr,
)

PLAINTEXT_3A = (
  ID_CRED_PSK : header_map / bstr / -24..23,
  CIPHERTEXT_3B : bstr,
)

PLAINTEXT_3B = (
  ? EAD_3
)

message_4 = (
  CIPHERTEXT_4 : bstr,
)

PLAINTEXT_4 = (
  ? EAD_4,
)

error = (
  ERR_CODE : int,
  ERR_INFO : any,
)

info = (
  info_label : int,
  context : bstr,
  length : uint,
)
~~~~~~~~~~~

# Test Vectors

## message_1

Both endpoints are authenticated with Pre-Shared Keys (METHOD = 4)

~~~~~~~~~~~~
METHOD (CBOR Data Item) (1 byte)
04
~~~~~~~~~~~~

The initiator selects cipher suite 0. A single cipher suite is encoded as an int:

~~~~~~~~~~~~
SUITES_I (CBOR Data Item) (1 byte)
00
~~~~~~~~~~~~

The Initiator creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~~~~~
Initiator's ephemeral private key
X (Raw Value) (32 bytes)
09 97 2D FE F1 EA AB 92 6E C9 6E 80 05 FE D2 9F 70 FF BF 4E
36 1C 3A 06 1A 7A CD B5 17 0C 10 E5
~~~~~~~~~~~~

~~~~~~~~~~~~
Initiator's ephemeral public key
G_X (Raw Value) (32 bytes)
7E C6 81 02 94 06 02 AA B5 48 53 9B F4 2A 35 99 2D 95 72 49
EB 7F 18 88 40 6D 17 8A 04 C9 12 DB
~~~~~~~~~~~~

The Initiator selects its connection identifier C_I to be the byte string 0xA, which is encoded as 0xA since it is represented by the 1-byte CBOR int 10:

~~~~~~~~~~~~
Connection identifier chosen by the Initiator
C_I (CBOR Data Item) (1 byte)
0A
~~~~~~~~~~~~

No external authorization data

~~~~~~~~~~~~
EAD_1 (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

The Initiator constructs message_1:

~~~~~~~~~~~~
message_1 (CBOR Sequence) (37 bytes)
05 02 58 20 7E C6 81 02 94 06 02 AA B5 48 53 9B F4 2A 35 99
2D 95 72 49 EB 7F 18 88 40 6D 17 8A 04 C9 12 DB 0A
~~~~~~~~~~~~

## message_2

The Responder supports the most preferred and selected cipher suite 0, so SUITES_I is acceptable.

The Responder creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~~~~~
Responder's ephemeral private key
Y (Raw Value) (32 bytes)
1E 1C 8F 2D F1 AA 71 10 B3 9F 33 BA 5E A8 DC CF 31 41 1E B3
3D 4F 9A 09 4C F6 51 92 D3 35 A7 A3
~~~~~~~~~~~~

~~~~~~~~~~~~
Responder's ephemeral public key
G_Y (Raw Value) (32 bytes)
ED 15 6A 62 43 E0 AF EC 9E FB AA BC E8 42 9D 5A D5 E4 E1 C4
32 F7 6A 6E DE 8F 79 24 7B B9 7D 83
~~~~~~~~~~~~

The Responder selects its connection identifier C_R to be the byte string 0x5, which is encoded as 0x5 since it is represented by the 1-byte CBOR int -10:

~~~~~~~~~~~~
Connection identifier chosen by the Responder
C_I (CBOR Data Item) (1 byte)
05
~~~~~~~~~~~~

The transcript hash TH_2 is calculated using the EDHOC hash algorithm:
TH_2 = H( G_Y, H(message_1) ), where H(message_1) is:

~~~~~~~~~~~~
H(message_1) (CBOR Data Item) (32 bytes)
22 4F 07 DF 2E 79 D7 38 00 50 E7 41 12 99 89 42 C0 D4 33 06
49 6C 39 0E 57 73 4A E8 42 0D 0A 2B
~~~~~~~~~~~~

~~~~~~~~~~~~
TH_2 (CBOR Data Item) (32 bytes)
27 6D 5C 44 F8 0E BD A7 CF 00 E0 47 3F E5 9D 10 E6 1C 2A 74
14 4B 87 AA D8 D4 F6 6C 39 7A 05 35
~~~~~~~~~~~~

PRK_2e is specified in {{Section 4.1.2 of RFC9528}}.
To compute it, the Elliptic Curve Diffie-Hellman (ECDH) shared secret G_XY is needed.
It is computed from G_X and Y or G_Y and X:

~~~~~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
2F 4A 79 9A 5A B0 C5 67 22 0C B6 72 08 E6 CF 8F 4C A5 FE 38
5D 1B 11 FD 9A 57 3D 41 60 F3 B0 B2
~~~~~~~~~~~~

Then, PRK_2e is calculated as defined in {{Section 4.1.2 of RFC9528}}

~~~~~~~~~~~~
PRK_2e (Raw Value) (32 bytes)
59 A2 15 55 E2 8A 1C CB 05 52 B4 5E 60 81 40 5F 3F 33 94 63 35
E0 14 53 A2 C7 7B FD E8 00 0E 04
~~~~~~~~~~~~

Since the Responder authenticates using PSK, PRK_3e2m = PRK_2e.

~~~~~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
59 A2 15 55 E2 8A 1C CB 05 52 B4 5E 60 81 40 5F 3F 33 94 63 35
E0 14 53 A2 C7 7B FD E8 00 0E 04
~~~~~~~~~~~~

No external authorization data:

~~~~~~~~~~~~
EAD_2 (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

The Responder constructs PLAINTEXT_2B:

~~~~~~~~~~~~
PLAINTEXT_2B (CBOR Sequence) (1 byte)
05
~~~~~~~~~~~~

The Responder computes KEYSTREAM_2 as defined in {{Section 4.1.2 of RFC9528}}

~~~~~~~~~~~~
KEYSTREAM_2 (CBOR Sequence) (1 byte)
31
~~~~~~~~~~~~

The Responder calculates CIPHERTEXT_2B as XOR between PLAINTEXT_2B and KEYSTREAM_2:

~~~~~~~~~~~~
CIPHERTEXT_2B (CBOR Sequence) (1 byte)
34
~~~~~~~~~~~~

The Responder constructs message_2 as defined in {{Section 5.3.1 of RFC9528}}:

~~~~~~~~~~~~
message_2 (CBOR Sequence) (35 bytes)
58 21 ED 15 6A 62 43 E0 AF EC 9E FB AA BC E8 42 9D 5A D5 E4
E1 C4 32 F7 6A 6E DE 8F 79 24 7B B9 7D 83 34
~~~~~~~~~~~~

## message_3

The Initiator computes PRK_4e3m, as described in Section 4, using SALT_4e3m:

~~~~~~~~~~~~
SALT_4e3m (Raw Value) (32 bytes)
3C 90 D8 EE A2 0E A7 34 41 62 36 1B 76 C2 7F BF 1F 11 FE CA
F3 8F F7 47 30 B1 12 11 42 74 1F 06
~~~~~~~~~~~~

~~~~~~~~~~~~
PRK_4e3m (Raw Value) (32 bytes)
FA B9 D7 69 88 9A 07 F1 93 8D E5 C7 DE 4D FB DF 80 9F B0 73
56 A8 2E 5A AB 04 91 8F 56 B2 19 BE
~~~~~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:

TH_3 = H( TH_2, PLAINTEXT_2 )

~~~~~~~~~~~~
TH_3 (CBOR Data Item) (32 bytes)
A5 0B 64 8C E2 A6 23 BF C9 72 15 B2 6C 7C EE BD C4 4F 6F 79
EF AA BE 27 E8 A0 2A 25 C0 C4 93 CC
~~~~~~~~~~~~

No external authorization data:

~~~~~~~~~~~~
EAD_3 (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

The Initiator constructs firstly PLAINTEXT_3B as defined in Section 5.3.1.:

~~~~~~~~~~~~
PLAINTEXT_3B (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

It then computes CIPHERTEXT_3B as defined in Section 5.3.2.:

~~~~~~~~~~~~
CIPHERTEXT_3B (CBOR Sequence) (9 bytes)
48 70 2A FB 75 AA 52 C4 89
~~~~~~~~~~~~

The Initiator computes KESYTREAM_3 as defined in Section 4:

~~~~~~~~~~~~
KESYTREAM_3 (CBOR Sequence) ()
D0 1B 7A AD 4C AB BD 14 89 50
~~~~~~~~~~~~

It then calculates PLAINTEXT_3A as stated in Section 5.3.2. and uses KESYTREAM_3 to derive CIPHERTEXT_3A:

~~~~~~~~~~~~
PLAINTEXT_3A (CBOR Sequence) (10 bytes)
10 48 70 2A FB 75 AA 52 C4 89
~~~~~~~~~~~~

~~~~~~~~~~~~
CIPHERTEXT_3A (CBOR Sequence) (10 bytes)
C0 53 0A 87 B7 DE 17 46 4D D9
~~~~~~~~~~~~

The initiator computes K_3 and IV_3

~~~~~~~~~~~~
K_3 (CBOR Sequence) (16 bytes)
D8 57 B9 46 46 34 25 35 3C 3C DE BD CB 90 CB 26
~~~~~~~~~~~~

~~~~~~~~~~~~
IV_3 (CBOR Sequence) (13 bytes)
A1 F6 BE AF 84 64 83 2A 8D 02 C8 5F 04
~~~~~~~~~~~~

The Initiator computes message_3 as defined in Section 5.3.2.:

~~~~~~~~~~~~
message_3 (CBOR Sequence) (11 bytes)
4A C0 53 0A 87 B7 DE 17 46 4D D9
~~~~~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:
TH_4 = H( TH_3, ID_CRED_PSK, ? EAD_3, CRED_PSK )

~~~~~~~~~~~~
TH_4 (CBOR Data Item) (32 bytes)
41 D7 D2 74 D2 23 E4 97 69 6E 1C BB 90 E2 F5 3F AD 2D 48 16
48 54 8F BD C7 E5 17 87 BC CD 79 B7
~~~~~~~~~~~~

## message_ 4

No external authorization data:

~~~~~~~~~~~~
EAD_4 (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

The Responder constructs PLAINTEXT_4:

~~~~~~~~~~~~
PLAINTEXT_4 (CBOR Sequence) (0 bytes)
~~~~~~~~~~~~

The Responder computes K_4 and IV_4

~~~~~~~~~~~~
K_4 (CBOR Sequence) (16 bytes)
53 05 7B 1F A7 F0 C8 3B 25 F6 A6 06 60 A2 8F EE
~~~~~~~~~~~~

~~~~~~~~~~~~
IV_4 (CBOR Sequence) (13 bytes)
D9 AB C3 DD E0 68 E9 4C 36 24 C0 EC 90
~~~~~~~~~~~~

The Responder computes message_4:

~~~~~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 E5 00 D1 2B BB D1 AE F1
~~~~~~~~~~~~

# Change Log

RFC Editor: Please remove this appendix.

* From -02 to -03

  * Updated abstract and Introduction
  * Changed message_3 to hide the identity lenght from passive attackers
  * CDDL Definitions
  * Security considerations of independence of Session Keys
  * Editorial changes

* From -01 to -02

  * Changes to message_3 formatting and processing

* From -00 to -01

  * Editorial changes and corrections

# Acknowledgments
{:numbered="false"}

The authors want to thank
{{{Christian Amsüss}}},
{{{Scott Fluhrer}}},
{{{Charlie Jacomme}}},
{{{Marco Tiloca}}},
and
{{{Francisco Lopez-Gomez}}}
for reviewing and commenting on intermediate versions of the draft.


This work has been partly funded by PID2023-148104OB-C43 funded by MICIU/AEI/10.13039/501100011033 (ONOFRE4), FEDER/UE EU HE CASTOR under Grant Agreement No 101167904 and EU CERTIFY under Grant Agreement No 101069471.
