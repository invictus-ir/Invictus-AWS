.. image:: /images/Invictus-Incident-Response.jpg
   :alt: Invictus logo
   
Invictus-AWS documentation!
===================================

Invictus-AWS is a python script that will help automatically enumerate and acquire relevant data from an AWS environment. The tool doesn't require any installation it can be run as a standalone script with minimal configuration required. The goal for Invictus-AWS is to allow incident responders or other security personnel to quickly get an insight into an AWS environment to answer the following questions:

* What services are running in an AWS environment.
* For each of the services what are the configuration details.
* What logging is available for each of the services that might be relevant in an incident response scenario.
* Is there any threat that I can find easily with the CloudTrail logs.

Want to know more about this project? We did a talk at FIRST Amsterdam 2022 and the slides are available here: https://github.com/invictus-ir/talks/blob/main/FIRST_2022_TC_AMS_Presentation.pdf

.. note::

   🆘 Incident Response support reach out to cert@invictus-ir.com or go to https://www.invictus-ir.com/247

Getting Help
------------

Have a bug report or feature request? Open an issue on the Github repository : https://github.com/invictus-ir/Invictus-AWS .

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Installation

   installation/start

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Operation

   use/work
   use/usage
   use/example