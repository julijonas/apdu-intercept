APDU interception
=================

This repository provides code for interception of smartcard application protocol data unit (APDU) commands
by listening and responding to messages received by a virtual smartcard driver.
It shows the hexadecimal traces in a hexdump format, logs them, colour-codes the APDU fields,
prints the descriptions for the detected inter-industry commands and responses,
and provides a hook to manipulate them.

It depends on the [Virtual Smart Card](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html) library.

To collect APDU traces make sure the smartcard is inserted, `pcscd` is running, smartcard can be found in `pcsc_scan`.
Then execute `intercept.py` using Python interpreter and use OpenSC, GnuPG, or your vendor's smartcard tools to
perform operations on the smartcard.

To perform MITM attack, the method `respond_to_message` in a class inherited from `InterceptAttack`
is the point where the attacker can issue commands and manipulate responses.

Virtual smartcard OS'es available using parameter `--os`:
* `RelayOS` that relays messages to another smartcard reader specified by `--reader`.
* `GemaltoOS` providing valid responses to authentication commands issued by Gemalto `libgclib.so`/`libgck2015x.so`
  Cryptoki libraries emulating Gemalto IDClassic 340.

Attack logic available using parameter `--attack`:
* `InterceptAttack` that just prints the sniffed APDU traces to stdout and `logs/date-time.log`.
* `GemaltoMITMAttack` that calculates parameters of secure messaging agreed between library and card.
* `YubikeyMITMAttack` that intercepts GENERATE ASYMMETRIC KEY PAIR, puts the attackers private key on card, and returns
  corresponding public key. 

The ISO inter-industry command/response descriptions are taken from the
[apdu-parser](https://github.com/eIDuy/apdu-parser) project.
