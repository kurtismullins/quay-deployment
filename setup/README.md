# ProjectQuay Deployment

The purpose of this repository is to provide an easy way to deploy everything
needed to run ProjectQuay on Openshift/OKD. Specifically, it has built with
the use-case of performance and scalability testing in mind.

At the time of writing, this repository contains two directories:
- quay-deployment
- setup

The `quay-deployment` directory contains a handful of `.yaml` files which can
be used to deploy Quay manually. The `setup` directory contains a Python-based
deployment. Both methods of deploying Quay are work-in-progress, although they
have been used to some extent already.

Notable References:
- [ProjectQuay](https://github.com/quay/quay)
- [quay_perf](https://github.com/jtaleric/quay_perf)
