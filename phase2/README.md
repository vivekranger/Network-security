
# Encryption of plain text

The encrypted messages were captures by wireshark and screenshots of the same have been attached along with the folder

# Mallory Attack Plan

The only point at which mallory could do MITM was before DH key exchange between server and client.

Using ARP spoofing and IP forwarding, announcements were made from mallory to the client wherein the server's IP was shown to be connected to mallory's Mac address and vice-versa with the server as well

The fingerprint printed by a client must match the fingerprint printed by the server for that particular connection.

For example:

Client fingerprint:
fd10f1438fa996e7803554825e6e4767f643ed61be5e2622487083b79622d5c

Mallory client-side fingerprint:
fd10f1438fa996e7803554825e6e4767f643ed61be5e2622487083b79622d5c

A different shared secret is established between Mallory and the server:

Mallory server-side fingerprint:
866471a0ecff40c41e3aec986b242b10f9a6774cb63591537b5c79fcfbab376

Server fingerprint:
866471a0ecff40c41e3aec986b242b10f9a6774cb63591537b5c79fcfbab376

The above fingerprints demonstrate that Mallory has created two separate Diffie-Hellman sessions.
