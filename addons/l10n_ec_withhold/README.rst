==============================================
Electronic Withholding Ecuadorian Localization
==============================================

.. 
   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
   !! This file is generated by oca-gen-addon-readme !!
   !! changes will be overwritten.                   !!
   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
   !! source digest: sha256:7112d6b82dea67ef127749269a0ea46d420d42b1de7c09da21b35480ac92afdb
   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

.. |badge1| image:: https://img.shields.io/badge/maturity-Beta-yellow.png
    :target: https://odoo-community.org/page/development-status
    :alt: Beta
.. |badge2| image:: https://img.shields.io/badge/licence-AGPL--3-blue.png
    :target: http://www.gnu.org/licenses/agpl-3.0-standalone.html
    :alt: License: AGPL-3
.. |badge3| image:: https://img.shields.io/badge/github-OCA%2Fl10n--ecuador-lightgray.png?logo=github
    :target: https://github.com/OCA/l10n-ecuador/tree/17.0/l10n_ec_withhold
    :alt: OCA/l10n-ecuador
.. |badge4| image:: https://img.shields.io/badge/weblate-Translate%20me-F47D42.png
    :target: https://translation.odoo-community.org/projects/l10n-ecuador-17-0/l10n-ecuador-17-0-l10n_ec_withhold
    :alt: Translate me on Weblate
.. |badge5| image:: https://img.shields.io/badge/runboat-Try%20me-875A7B.png
    :target: https://runboat.odoo-community.org/builds?repo=OCA/l10n-ecuador&target_branch=17.0
    :alt: Try me on Runboat

|badge1| |badge2| |badge3| |badge4| |badge5|

The ``l10n_ec_withhold`` module is designed to facilitate the management
of withholding taxes in the context of Ecuadorian localization.
Withholding taxes play a crucial role in financial transactions, both in
the procurement of goods and services (purchases) and the sale of
products or services (sales). This module streamlines the process of
handling withholding taxes, ensuring compliance with Ecuadorian tax
regulations.

**Table of contents**

.. contents::
   :local:

Usage
=====

To effectively utilize the ``l10n_ec_withhold`` module, follow these
essential steps:

1. **Journal, Agencies, and Emission Points Configuration:**

   For each journal, specify whether it will be used for withholding
   taxes on purchases or withholding taxes on sales. This can be
   configured in the journal settings.

   .. code:: markdown

      - Navigate to Invoicing > Configuration > Accounting > Journals.
      - Set up relevant journals for electronic withholding.

2. **XML Code Configuration in Taxes:** In order to align with
   Ecuadorian tax reporting requirements, the module introduces a
   feature where users must configure XML codes for taxes. This ensures
   that the generated tax reports comply with the specified XML
   standards mandated by local tax authorities.

3. **Tax Support Configuration:** Users can now configure the "Tax
   Support" (tax justification) at both the line level and the invoice
   level. This flexibility allows businesses to provide detailed tax
   justifications for individual line items, enhancing transparency in
   tax documentation. Additionally, users have the option to set a
   global "Tax Support" at the invoice level, providing a comprehensive
   view of the tax justifications for the entire document.

4. **Position Fiscal Activation for Withholding Taxes:** To enable the
   withholding tax functionality seamlessly, users need to activate it
   in the fiscal position settings for both the supplier and the
   company. This ensures that the system takes into account the specific
   fiscal requirements related to withholding taxes during transactions
   with the designated supplier.

Bug Tracker
===========

Bugs are tracked on `GitHub Issues <https://github.com/OCA/l10n-ecuador/issues>`_.
In case of trouble, please check there if your issue has already been reported.
If you spotted it first, help us to smash it by providing a detailed and welcomed
`feedback <https://github.com/OCA/l10n-ecuador/issues/new?body=module:%20l10n_ec_withhold%0Aversion:%2017.0%0A%0A**Steps%20to%20reproduce**%0A-%20...%0A%0A**Current%20behavior**%0A%0A**Expected%20behavior**>`_.

Do not contact contributors directly about support or help with technical issues.

Credits
=======

Authors
-------

* Odoo-EC

Contributors
------------

-  Leonardo Gomez (https://github.com/gomezgleonardob)
-  Ricardo Jara (https://github.com/rvjaraj)
-  Jorge Luis (https://github.com/mestizosdev)
-  Luis Romero (https://github.com/lojanet)
-  Carlos Lopez (https://github.com/celm1990)

Maintainers
-----------

This module is maintained by the OCA.

.. image:: https://odoo-community.org/logo.png
   :alt: Odoo Community Association
   :target: https://odoo-community.org

OCA, or the Odoo Community Association, is a nonprofit organization whose
mission is to support the collaborative development of Odoo features and
promote its widespread use.

This module is part of the `OCA/l10n-ecuador <https://github.com/OCA/l10n-ecuador/tree/17.0/l10n_ec_withhold>`_ project on GitHub.

You are welcome to contribute. To learn how please visit https://odoo-community.org/page/Contribute.
