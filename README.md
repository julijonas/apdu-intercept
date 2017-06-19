APDU interception
=================

This repository provides code for interception of smart card application protocol data unit (APDU) commands.
It shows the hexadecimal traces in a hexdump format, logs them, colour-codes the APDU fields,
prints the descriptions for the detected inter-industry commands and responses,
and provides a hook to manipulate them.

It depends on the [Virtual Smart Card](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html) library.

To collect APDU traces make sure the smart card is inserted, `pcscd` is running, smart card can be found in `pcsc_scan`.
Then execute `intercept.py` using Python interpreter and use OpenSC, GnuPG, or your vendor's smart card tools to
perform operations on the smart card.

To perform MITM attack, the method `respond` in `MITMAttack` class is the point where the commands and responses can
be manipulated.

The command/response descriptions are taken from the [apdu-parser](https://github.com/eIDuy/apdu-parser) project.
