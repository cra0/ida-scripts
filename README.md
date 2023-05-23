# ida-scripts
Various IDA scripts I've created for Reverse Engineering.

## Plugins

> [plugins/](plugins/plugins-readme.md)

## Scripts

### Cra0 Signature Definition File Importer
*Imports CSDF files into IDA see [scripts/csdf_importer](scripts/csdf_importer/csdf-info.md) for further information.*

* In IDA go `File -> Script File..` and select `apply_signatures.idc`
* It will prompt you for the csdf file, locate it and click Open.

### Cra0 VTable Definition File Importer
*Imports CVDF files into IDA see [scripts/cvdf_importer](scripts/cvdf_importer/cvdf-info.md) for further information.*

* In IDA go `File -> Script File..` and select `apply_vtables.idc`
* It will prompt you for the cvdf file, locate it and click Open.

### Misc
Miscellaneous scripts that do various things.