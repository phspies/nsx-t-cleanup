package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	nsxt "../nsxt30_policy_api"
	"github.com/antihax/optional"
)

func main() {

	config := nsxt.Configuration{
		Host:                 "192.168.2.20",
		BasePath:             "/policy/api/v1",
		Scheme:               "https",
		DefaultHeader:        map[string]string{"X-Allow-Overwrite": "true"},
		UserName:             "admin",
		Password:             "VMware1!VMware1!",
		Insecure:             true,
		RemoteAuth:           false,
		RetriesConfiguration: nsxt.ClientRetriesConfiguration{MaxRetries: 3, RetryMaxDelay: 10},
	}
	var searchscope = "tags.scope:*ncp*"

	nsxtClient, _error := nsxt.NewAPIClient(&config)
	if _error != nil {
		log.Panicf("Error getting auth token: %s", _error)
	}
	_context := nsxtClient.Context
	var search = searchscope + " AND _exists_:resource_type AND !_exists_:nsx_id AND !resource_type:(Domain) AND !_create_user:nsx_policy"
	options := nsxt.SearchSearchApiQuerySearchGroupByOpts{
		GroupCount:           optional.NewInt64(100),
		DataSource:           optional.NewString("ALL"),
		ExcludeInternalTypes: optional.NewBool(true),
	}
	searchResults, _, _error := nsxtClient.SearchApi.GroupByQuerySearch(_context, search, &options)
	if _error != nil {
		log.Fatalf("Error running search: %s", _error)
		os.Exit(1)
	}
	for _, group := range searchResults.Results {
		fmt.Printf("\tFound %d %s's\n", group.Count, group.GroupByFieldValue)
	}
	var _order = [...]string{
		"SpoofGuardProfile",
		"SecurityPolicy",
		"LBVirtualServer",
		"LBService",
		"Group",
		"Segment",
		"PolicyNatRule",
		"LBPool",
		"LBHttpProfile",
		"LBFastTcpProfile",
		"LBFastUdpProfile",
		"LBSourceIpPersistenceProfile",
		"IpAddressAllocation",
		"IpAddressPool",
		"IpAddressBlock",
		"Tier1",
		"TlsCertificate",
	}
	for _, subsystem := range _order {
		fmt.Printf("Processing %s\n", subsystem)
		var search = "resource_type:" + subsystem + " AND tags.scope:*ncp* AND _exists_:resource_type AND !_exists_:nsx_id AND !resource_type:(Domain) AND !_create_user:nsx_policy"
		options := nsxt.SearchSearchApiQuerySearchOpts{
			PageSize: optional.NewInt64(50),
		}
		searchResults2, _, _error := nsxtClient.SearchApi.QuerySearch(_context, search, &options)
		fmt.Printf("\tFound %d %s's\n", searchResults2.ResultCount, subsystem)

		if _error != nil {
			log.Fatalf("Error running search: %s", _error)
			os.Exit(1)
		}
		if subsystem == "SpoofGuardProfile" {
			for _, sgprofiles := range searchResults2.Results {
				bytes, err := json.Marshal(sgprofiles)
				if err != nil {
					panic(err)
				}
				var pgprofile nsxt.SpoofGuardProfile
				if err := json.Unmarshal(bytes, &pgprofile); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting spoofguard profile: %s\n", pgprofile.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteSpoofGuardProfile(_context, pgprofile.ID)
				if error != nil {
					panic(error)
				}
			}
		}
		if subsystem == "SecurityPolicy" {
			for _, _policy := range searchResults2.Results {
				bytes, err := json.Marshal(_policy)
				if err != nil {
					panic(err)
				}
				var policy nsxt.SecurityPolicy
				if err := json.Unmarshal(bytes, &policy); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting security policy with rules: %s\n", policy.DisplayName)
				var domainID = strings.Split(policy.Path, "/")[3]
				_, error := nsxtClient.PolicySecurityApi.DeleteSecurityPolicyForDomain(_context, domainID, policy.ID)
				if error != nil {
					panic(error)
				}
			}
		}

		if subsystem == "LBVirtualServer" {
			for _, LbvServer := range searchResults2.Results {
				bytes, err := json.Marshal(LbvServer)
				if err != nil {
					panic(err)
				}
				var lbVirtService nsxt.LbVirtualServer
				if err := json.Unmarshal(bytes, &lbVirtService); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting LB vServer: %s\n", lbVirtService.DisplayName)
				httpResponse, error := nsxtClient.PolicyNetworkingApi.DeleteLBVirtualServer(_context, lbVirtService.ID, nil)
				_ = httpResponse
				if error != nil {
					panic(error)
				}
			}
		}
		if subsystem == "LBService" {
			for _, lbService := range searchResults2.Results {
				bytes, err := json.Marshal(lbService)
				if err != nil {
					panic(err)
				}
				var LBService nsxt.LbService
				if err := json.Unmarshal(bytes, &LBService); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting LBService: %s\n", LBService.DisplayName)
				httpResponse, error := nsxtClient.PolicyNetworkingApi.DeleteLBService(_context, LBService.ID, nil)
				_ = httpResponse
				if error != nil {
					panic(error)
				}
			}
		}
		if subsystem == "Group" {
			for _, _group := range searchResults2.Results {
				bytes, err := json.Marshal(_group)
				if err != nil {
					panic(err)
				}
				var group nsxt.Group
				if err := json.Unmarshal(bytes, &group); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting group: %s\n", group.DisplayName)
				var domainID = strings.Split(group.Path, "/")[3]
				_, error := nsxtClient.PolicyInventoryApi.DeleteGroup(_context, domainID, group.ID, &nsxt.PolicyInventoryApiDeleteGroupOpts{FailIfSubtreeExists: optional.NewBool(false), Force: optional.NewBool(true)})
				if error != nil {
					panic(error)
				}
			}
		}
		if subsystem == "Segment" {
			for _, segment := range searchResults2.Results {
				bytes, err := json.Marshal(segment)
				if err != nil {
					panic(err)
				}
				var segment nsxt.Segment
				if err := json.Unmarshal(bytes, &segment); err != nil {
					panic(err)
				}
				fmt.Printf("\tGetting segment security binding for: %s\n", segment.DisplayName)
				securityBindings, _, error := nsxtClient.PolicyNetworkingApi.ListInfraSegmentSecurityProfileBindings(_context, segment.ID, nil)
				if error != nil {
					panic(error)
				}
				for _, binding := range securityBindings.Results {
					fmt.Printf("\t\tDeleting segment security binding: %s\n", binding.DisplayName)

					_, error := nsxtClient.PolicyNetworkingApi.DeleteInfraSegmentSecurityProfileBinding(_context, segment.ID, binding.ID)
					if error != nil {
						panic(error)
					}
				}
				segmentPorts, _, segmentPortsError := nsxtClient.PolicyNetworkingApi.ListInfraSegmentPorts(_context, segment.ID, nil)
				if segmentPortsError != nil {
					panic(segmentPortsError)
				}
				fmt.Printf("\t\t\tFound %d segment ports\n", segmentPorts.ResultCount)

				for _, segmentPort := range segmentPorts.Results {
					fmt.Printf("\t\t\tDeleting segment port: %s\n", segmentPort.DisplayName)
					_, segportdelerror := nsxtClient.PolicyNetworkingApi.DeleteInfraSegmentPort(_context, segment.ID, segmentPort.ID)
					if segportdelerror != nil {
						panic(segportdelerror)
					}
				}
				fmt.Printf("\t\t\tDeleting segment: %s\n", segment.DisplayName)
				_, delSegmentError := nsxtClient.PolicyNetworkingApi.ForceDeleteInfraSegmentTrue(_context, segment.ID)
				if delSegmentError != nil {
					panic(delSegmentError)
				}
			}
		}
		if subsystem == "PolicyNatRule" {
			for _, natrule := range searchResults2.Results {
				bytes, err := json.Marshal(natrule)
				if err != nil {
					panic(err)
				}
				var policyNatRule nsxt.PolicyNatRule
				if err := json.Unmarshal(bytes, &policyNatRule); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting Policy NAT Rule: %s\n", policyNatRule.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeletePolicyNatRule(_context, policyNatRule.Path)
				if error != nil {
					panic(error)
				}

			}
		}
		if subsystem == "LBPool" {
			for _, lbpool := range searchResults2.Results {
				bytes, err := json.Marshal(lbpool)
				if err != nil {
					panic(err)
				}
				var lbPool nsxt.LbPool
				if err := json.Unmarshal(bytes, &lbPool); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting Load Balancer Pool: %s\n", lbPool.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteLBPool(_context, lbPool.Path, &nsxt.PolicyNetworkingApiDeleteLBPoolOpts{Force: optional.NewBool(true)})
				if error != nil {
					panic(error)
				}

			}
		}
		if subsystem == "LBHttpProfile" || subsystem == "LBFastUdpProfile" || subsystem == "LBFastTcpProfile" {
			for _, lbHTTPProfile := range searchResults2.Results {
				bytes, err := json.Marshal(lbHTTPProfile)
				if err != nil {
					panic(err)
				}
				var LBhttpProfile nsxt.LbHttpProfile
				if err := json.Unmarshal(bytes, &LBhttpProfile); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting LB Http Profile: %s\n", LBhttpProfile.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteLBAppProfile(_context, LBhttpProfile.Path, &nsxt.PolicyNetworkingApiDeleteLBAppProfileOpts{Force: optional.NewBool(true)})
				if error != nil {
					panic(error)
				}

			}
		}
		if subsystem == "LBSourceIpPersistenceProfile" {
			for _, lbPersistantProfile := range searchResults2.Results {
				bytes, err := json.Marshal(lbPersistantProfile)
				if err != nil {
					panic(err)
				}
				var lbPersistantIPProfile nsxt.LbSourceIpPersistenceProfile
				if err := json.Unmarshal(bytes, &lbPersistantIPProfile); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting LB Http Profile: %s\n", lbPersistantIPProfile.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteLBPersistenceProfile(_context, lbPersistantIPProfile.Path, &nsxt.PolicyNetworkingApiDeleteLBPersistenceProfileOpts{Force: optional.NewBool(true)})
				if error != nil {
					panic(error)
				}

			}
		}

		if subsystem == "IpAddressPool" {
			for _, ipAddressPool := range searchResults2.Results {
				bytes, err := json.Marshal(ipAddressPool)
				if err != nil {
					panic(err)
				}
				var IPAddressPool nsxt.IpAddressPool
				if err := json.Unmarshal(bytes, &IPAddressPool); err != nil {
					panic(err)
				}
				subnets, _, subneterror := nsxtClient.PolicyNetworkingApi.ListIpAddressPoolSubnets(_context, IPAddressPool.ID, nil)
				if subneterror != nil {
					panic(subneterror)
				}
				for _, subnet := range subnets.Results {
					bytes, err := json.Marshal(subnet)
					if err != nil {
						panic(err)
					}
					var IPAddressPoolSubnet nsxt.IpAddressPoolSubnet
					if err := json.Unmarshal(bytes, &IPAddressPoolSubnet); err != nil {
						panic(err)
					}
					fmt.Printf("\t\tDeleting: %s\n", IPAddressPoolSubnet.DisplayName)
					_, error := nsxtClient.PolicyNetworkingApi.DeleteIpAddressPoolSubnet(_context, IPAddressPoolSubnet.Path)
					if error != nil {
						panic(error)
					}
				}

				fmt.Printf("\tDeleting: %s\n", IPAddressPool.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteIpAddressPool(_context, IPAddressPool.Path)
				if error != nil {
					panic(error)
				}

			}
		}
		if subsystem == "IpAddressAllocation" {
			for _, ipAddressalloc := range searchResults2.Results {
				bytes, err := json.Marshal(ipAddressalloc)
				if err != nil {
					panic(err)
				}
				var ipAddressAlloc nsxt.IpAddressAllocation
				if err := json.Unmarshal(bytes, &ipAddressAlloc); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting: %s\n", ipAddressAlloc.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteIpAddressPoolAllocation(_context, ipAddressAlloc.Path)
				if error != nil {
					panic(error)
				}

			}
		}
		if subsystem == "IpAddressBlock" {
			for _, IpAddressblock := range searchResults2.Results {
				bytes, err := json.Marshal(IpAddressblock)
				if err != nil {
					panic(err)
				}
				var IPAddressBlock nsxt.IpAddressBlock
				if err := json.Unmarshal(bytes, &IPAddressBlock); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting: %s\n", IPAddressBlock.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteIpAddressBlock(_context, IPAddressBlock.Path)
				if error != nil {
					panic(error)
				}

			}
		}

		if subsystem == "Tier1" {
			for _, tier1 := range searchResults2.Results {
				bytes, err := json.Marshal(tier1)
				if err != nil {
					panic(err)
				}
				var TIER1 nsxt.Tier1
				if err := json.Unmarshal(bytes, &TIER1); err != nil {
					panic(err)
				}
				localeservices, _, localeserviceserror := nsxtClient.PolicyNetworkingApi.ListTier1LocaleServices(_context, TIER1.ID, nil)
				if localeserviceserror != nil {
					panic(localeserviceserror)
				}
				for _, localeService := range localeservices.Results {
					bytes, err := json.Marshal(localeService)
					if err != nil {
						panic(err)
					}
					var LocaleService nsxt.LocaleServices
					if err := json.Unmarshal(bytes, &LocaleService); err != nil {
						panic(err)
					}
					fmt.Printf("\t\t\tDeleting Locale Service: %s\n", LocaleService.DisplayName)
					_, error := nsxtClient.PolicyNetworkingApi.DeleteTier1LocaleServices(_context, LocaleService.Path)
					if error != nil {
						panic(error)
					}
				}

				fmt.Printf("\tDeleting: %s\n", TIER1.DisplayName)
				_, error := nsxtClient.PolicyNetworkingApi.DeleteTier1(_context, TIER1.Path)
				if error != nil {
					panic(error)
				}

			}
		}

		if subsystem == "TlsCertificate" {
			for _, tlsCertificate := range searchResults2.Results {
				bytes, err := json.Marshal(tlsCertificate)
				if err != nil {
					panic(err)
				}
				var TLSCertificate nsxt.TlsCertificate
				if err := json.Unmarshal(bytes, &TLSCertificate); err != nil {
					panic(err)
				}
				fmt.Printf("\tDeleting: %s\n", TLSCertificate.DisplayName)
				_, error := nsxtClient.PolicyInfraApi.DeleteTlsCertificate(_context, TLSCertificate.Path)
				if error != nil {
					panic(error)
				}

			}
		}
	}
}
