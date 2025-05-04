# malduck-modules

## What is this

This is a repository with sample [malduck🦆](https://github.com/CERT-Polska/malduck) config extraction modules. By utilizing them you should be able to extract embedded configuration from unpacked malware samples of:
* njrat
* remcos
* revil
* graphicalproton
* cobalt strike

## Usage

To install:
```shell
pip install malduck
```

To install the cobalt strike configuration extractor
```shell
pip install libcsce
```

To run the config extractor:
```shell
malduck extract --modules modules/ samples_directory/
```

## Samples

We've collected several malware samples that you should be able to extract using the extraction modules provided:

* [`win_njrat_66969ca6880e2ff107b78ea8a8ea31900912a8e3c910c336134f8cf78cc39a75`](https://bazaar.abuse.ch/sample/66969ca6880e2ff107b78ea8a8ea31900912a8e3c910c336134f8cf78cc39a75/)
* [`win_njrat_d5287df696839eaff465b707962ff9ca0b5235a4890dc19465e3e4afde84013e`](https://bazaar.abuse.ch/sample/d5287df696839eaff465b707962ff9ca0b5235a4890dc19465e3e4afde84013e/)
* [`win_njrat_ee98deeca8c3daf8c538198639864c18677f59fd68bf130920c51af737bca710`](https://bazaar.abuse.ch/sample/ee98deeca8c3daf8c538198639864c18677f59fd68bf130920c51af737bca710/)

* [`win_remcos_1984264959b7d63e516544cbce4b6dffb7ed5210a472437dd88068f4d39600e2`](https://bazaar.abuse.ch/sample/1984264959b7d63e516544cbce4b6dffb7ed5210a472437dd88068f4d39600e2)
* [`win_remcos_3ec2af4b5c9bb02513b905dfa7217efdcec08dce2c3d9621bd4792d50e548cf1`](https://bazaar.abuse.ch/sample/3ec2af4b5c9bb02513b905dfa7217efdcec08dce2c3d9621bd4792d50e548cf1)
* [`win_remcos_ba0ebdbc3867696b266eed6a797b9ca9d7c7b9ae88e6190dcc62c9ba88d9eb8a`](https://bazaar.abuse.ch/sample/ba0ebdbc3867696b266eed6a797b9ca9d7c7b9ae88e6190dcc62c9ba88d9eb8a)

* [`win_revil_3cff33197edc918d47d08f44d6ddbdda157337f0ad58288d15746cf72c0e4c57`](https://bazaar.abuse.ch/sample/3cff33197edc918d47d08f44d6ddbdda157337f0ad58288d15746cf72c0e4c57)
* [`win_revil_42c28feb23c992a350673d63413bf11bc816d00a079462ab524934219d46430d`](https://bazaar.abuse.ch/sample/42c28feb23c992a350673d63413bf11bc816d00a079462ab524934219d46430d)
* [`win_revil_6628de7ffbbe168a4fa9ff0a1a29b54e88a32e5963db0dd1aea4b80102c8ce01`](https://bazaar.abuse.ch/sample/6628de7ffbbe168a4fa9ff0a1a29b54e88a32e5963db0dd1aea4b80102c8ce01)

* [`win_graphical_proton_46299f696566a15638b4fdeffe91dc01ab1e4e07e980573c29531f1bc49d33f0`](https://bazaar.abuse.ch/sample/46299f696566a15638b4fdeffe91dc01ab1e4e07e980573c29531f1bc49d33f0)
* [`win_graphical_proton_c7b01242d2e15c3da0f45b8adec4e6913e534849cde16a2a6c480045e03fbee4`](https://bazaar.abuse.ch/sample/c7b01242d2e15c3da0f45b8adec4e6913e534849cde16a2a6c480045e03fbee4)
* [`win_graphical_proton_dc79c213a28493bb4ba2c8e274696a41530a5983c7a3586b31ff69a5291754e6`](https://bazaar.abuse.ch/sample/dc79c213a28493bb4ba2c8e274696a41530a5983c7a3586b31ff69a5291754e6)

* [`win_cobalt_strike_e48176cbdc36ab68a2299bdd589e7b4358086dcb4da30fedc56b07104efc4726`](https://bazaar.abuse.ch/sample/e48176cbdc36ab68a2299bdd589e7b4358086dcb4da30fedc56b07104efc4726)
* [`win_cobalt_strike_6cdf4ef384200493d95a03c2b5fac127ce7c47be5313edb7410199184bb0bcb2`](https://bazaar.abuse.ch/sample/6cdf4ef384200493d95a03c2b5fac127ce7c47be5313edb7410199184bb0bcb2)

## Learning more and creating your own modules

You should be able to grasp the basic nuances by looking at the module sources and the [configuration extractor docs](https://malduck.readthedocs.io/en/latest/extractor.html). Additionally, the [karton gems series](https://cert.pl/en/posts/2021/05/karton-gems-3-malware-extraction/) provides a very good overlook of a simple citadel module.
