# Copyright 2026 Tulip Labs
# SPDX-License-Identifier: Apache-2.0

"""tulip-integrations — community security integrations for the Tulip SDK.

Vendor templates (SIEM / EDR / threat-intel / posture) and community playbooks
that plug into the core ``tulip-agents`` SDK. The dependency is one-way:
integrations import the core ``tulip.security`` contracts; core never imports
this package. Discover an integration by **explicit import** and wire it in via
``tulip.security.security_toolset(extra=[...])``.
"""

__version__ = "0.1.0"
