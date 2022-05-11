#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Hidden or not exposed URLS
_SITE_URL = '/infra/sites'
_DOMAIN_URL = '/infra/domains'
_ENFORCEMENT_POINT_URL = _SITE_URL + '/{}/enforcement-points'

IP_BLOCK_URL = '/infra/ip-blocks'

IP_POOL_URL = '/infra/ip-pools'
IP_ADDRESS_POOL_SUBNET_URL = IP_POOL_URL + '/{}/ip-subnets'

POLICY_GROUP_URL = _DOMAIN_URL + '/{}/groups'

SECURITY_POLICY_URL = _DOMAIN_URL + '/{}/security-policies'

SEGMENT_URL = '/infra/segments'
SEGMENT_PORT_URL = SEGMENT_URL + '/{}/ports'

TRANSPORT_ZONE_URL = _ENFORCEMENT_POINT_URL + '/{}/transport-zones'

L2_BRIDGE_EP_PROFILE_URL = _ENFORCEMENT_POINT_URL + '/{}/edge-bridge-profiles'

TIER_0_URL = '/infra/tier-0s'
TIER_0_STATIC_ROUTE_URL = TIER_0_URL + '/{}/static-routes'
TIER_0_LOCALE_SERVICE_URL = TIER_0_URL + '/{}/locale-services'
TIER_0_LS_INTERFACE_URL = TIER_0_LOCALE_SERVICE_URL + '/{}/interfaces'
TIER_0_BGP_NEIGHBOR_URL = TIER_0_LOCALE_SERVICE_URL + '/{}/bgp/neighbors'
TIER_0_BFD_PEERS = TIER_0_STATIC_ROUTE_URL + '/bfd-peers'

TIER_1_URL = '/infra/tier-1s'
TIER_1_STATIC_ROUTE_URL = TIER_1_URL + '/{}/static-routes'
TIER_1_LOCALE_SERVICE_URL = TIER_1_URL + '/{}/locale-services'
TIER_1_LS_INTERFACE_URL = TIER_1_LOCALE_SERVICE_URL + '/{}/interfaces'
TIER_1_BGP_NEIGHBOR_URL = TIER_1_LOCALE_SERVICE_URL + '/{}/bgp/neighbors'

IPV6_DAD_PROFILE_URL = '/infra/ipv6-dad-profiles'
IPV6_NDRA_PROFILE_URL = '/infra/ipv6-ndra-profiles'

DHCP_RELAY_CONFIG_URL = '/infra/dhcp-relay-configs'

EDGE_CLUSTER_URL = _ENFORCEMENT_POINT_URL + '/{}/edge-clusters'
EDGE_NODE_URL = EDGE_CLUSTER_URL + '/{}/edge-nodes'

VM_LIST_URL = '/infra/realized-state/virtual-machines'
VM_UPDATE_URL = ('/infra/realized-state/enforcement-points/' +
                 'default/virtual-machines')

BFD_PROFILE_URL = '/infra/bfd-profiles'

GATEWAY_POLICY_URL = _DOMAIN_URL + '/{}/gateway-policies'

LOCAL_POLICY_URL = '/policy/api/v1/infra'
GLOBAL_POLICY_URL = '/global-manager/api/v1/global-infra'
