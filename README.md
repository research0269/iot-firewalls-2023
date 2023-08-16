# Code Submission for IMWUT 2023

The repository contains code that can create allowlists, evaluate them, and the proof-of-concept of a firewall that supports hosts representations like hostname, domain name, and hostname patterns.

We cannot share the data due to IRB restrictions, but we include a sample data that is available to the public by the authors of the IoT Inspector project. The sample data contains devices and traffic that are from a lab setting (the lab that created the IoT Inspector), and each product only has one device instance. This kind of data cannot work with the majority of the evaluation code, as most of our evaluation is about creating allowlists from some devices of a product, and then applying them on the rest.

The code for generating the figures in Section 4, 5, and 6 are placed under `eval_src`, while the code for the firewall implementation (Section 6) is placed under `firewalls_src`.
