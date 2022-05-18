// Copyright 2016-2022, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"sort"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type vpcEndpointSpecsInput struct {
	AutoAccept        bool              `pulumi:"autoAccept"`
	Policy            string            `pulumi:"policy"`
	PrivateDNSEnabled bool              `pulumi:"privateDnsEnabled"`
	RouteTableIds     []string          `pulumi:"routeTableIds"`
	SecurityGroupIds  []string          `pulumi:"securityGroupIds"`
	ServiceName       string            `pulumi:"serviceName"`
	SubnetIds         []string          `pulumi:"subnetIds"`
	Tags              map[string]string `pulumi:"tags"`
	VpcEndpointType   string            `pulumi:"vpcEndpointType"`
}

type subnetSpecInput struct {
	CIDRMask int    `pulumi:"cidrMask"`
	Name     string `pulumi:"name"`
	Type     string `pulumi:"type"`
}

type natGatewayInput struct {
	ElasticIpAllocationIds []string `pulumi:"elasticIpAllocationIds"`
	Strategy               string   `pulumi:"strategy"`
}

type VPCArgs struct {
	AssignGeneratedIpv6CidrBlock    bool                    `pulumi:"assignGeneratedIpv6CidrBlock"`
	AvailabilityZoneNames           []string                `pulumi:"availabilityZoneNames"`
	CIDRBlock                       string                  `pulumi:"cidrBlock"`
	EnableClassiclink               bool                    `pulumi:"enableClassiclink"`
	EnableClassiclinkDNSSupport     bool                    `pulumi:"enableClassiclinkDnsSupport"`
	EnableDNSHostnames              bool                    `pulumi:"enableDnsHostnames"`
	EnableDNSSuport                 bool                    `pulumi:"enableDnsSupport"`
	InstanceTenancy                 string                  `pulumi:"instanceTenancy"`
	Ipv4IpamPoolId                  string                  `pulumi:"ipv4IpamPoolId"`
	Ipv4NetmaskLength               int                     `pulumi:"ipv4NetmaskLength"`
	Ipv6CidrBlock                   string                  `pulumi:"ipv6CidrBlock"`
	Ipv6CidrBlockNetworkBorderGroup string                  `pulumi:"ipv6CidrBlockNetworkBorderGroup"`
	Ipv6IpamPoolId                  string                  `pulumi:"ipv6IpamPoolId"`
	Ipv6NetmaskLength               int                     `pulumi:"ipv6NetmaskLength"`
	NatGateways                     natGatewayInput         `pulumi:"natGateways"`
	NumberOfAvailabilityZones       int                     `pulumi:"numberOfAvailabilityZones"`
	SubnetSpecs                     []subnetSpecInput       `pulumi:"subnetSpecs"`
	Tags                            map[string]string       `pulumi:"tags"`
	VpcEndpointSpecs                []vpcEndpointSpecsInput `pulumi:"vpcEndpointSpecs"`
}

type VPCOutput struct {
	pulumi.ResourceState

	EIPS                   []*ec2.Eip                   `pulumi:"eips"`
	InternetGateway        *ec2.InternetGateway         `pulumi:"internetGateway"`
	NatGateways            []*ec2.NatGateway            `pulumi:"natGateways"`
	RouteTableAssociations []*ec2.RouteTableAssociation `pulumi:"routeTableAssociations"`
	RouteTables            []*ec2.RouteTable            `pulumi:"routeTables"`
	Routes                 []*ec2.Route                 `pulumi:"routes"`
	Subnets                []*ec2.Subnet                `pulumi:"subnets"`
	VPC                    *ec2.Vpc                     `pulumi:"vpc"`
	VPCEndpoints           []*ec2.VpcEndpoint           `pulumi:"vpcEndpoints"`
	VPCID                  pulumi.IDOutput              `pulumi:"vpcId"`
	PublicSubnetIDs        pulumi.IDArrayOutput         `pulumi:"publicSubnetIds"`
	PrivateSubnetIDs       pulumi.IDArrayOutput         `pulumi:"privateSubnetIds"`
	IsolatedSubnetIDs      pulumi.IDArrayOutput         `pulumi:"isolatedSubnetIds"`
}

func NewVPC(ctx *pulumi.Context, name string, args *VPCArgs, opts ...pulumi.ResourceOption) (*VPCOutput, error) {
	if args == nil {
		args = &VPCArgs{}
	}

	component := &VPCOutput{}
	err := ctx.RegisterComponentResource("aws-vpc:index:Vpc", name, component, opts...)
	if err != nil {
		return nil, err
	}

	if (len(args.AvailabilityZoneNames) > 0) && (args.NumberOfAvailabilityZones > 0) {
		return nil, fmt.Errorf("Only one of [availabilityZoneNames] and [numberOfAvailabilityZones] can be specified")
	}

	availabilityZones := args.AvailabilityZoneNames
	if len(availabilityZones) == 0 {
		desiredCount := args.NumberOfAvailabilityZones
		if desiredCount == 0 {
			desiredCount = 3
		}

		azs, err := aws.GetAvailabilityZones(ctx, &aws.GetAvailabilityZonesArgs{})
		if err != nil {
			return nil, err
		}

		if len(azs.Names) < desiredCount {
			return nil, fmt.Errorf("The configured region for this provider does not have at least %v Availability Zones. Either specify an explicit list of zones in availabilityZoneNames or choose a region with at least %v AZs.", desiredCount, desiredCount)
		}

		availabilityZones = azs.Names
	}

	allocationIds := args.NatGateways.ElasticIpAllocationIds
	natGatewayStrategy := args.NatGateways.Strategy
	if natGatewayStrategy == "" {
		natGatewayStrategy = "OnePerAz"
	}

	err = validateEips(natGatewayStrategy, allocationIds, availabilityZones)
	if err != nil {
		return nil, err
	}

	cidrBlock := args.CIDRBlock
	if cidrBlock == "" {
		cidrBlock = "10.0.0.0/16"
	}

	subnetSpecs, err := getSubnetSpecs(name, cidrBlock, availabilityZones, args.SubnetSpecs)
	if err != nil {
		return nil, err
	}

	err = validateSubnets(subnetSpecs)
	if err != nil {
		return nil, err
	}

	err = validateNatGatewayStrategy(natGatewayStrategy, subnetSpecs)
	if err != nil {
		return nil, err
	}

	vpcTags := map[string]string{
		"Name": name,
	}
	for tagKey, tagValue := range args.Tags {
		vpcTags[tagKey] = tagValue
	}

	instanceTenancy := args.InstanceTenancy
	if instanceTenancy == "" {
		instanceTenancy = "dedicated"
	}

	vpcArgs := &ec2.VpcArgs{
		CidrBlock:                   pulumi.StringPtr(cidrBlock),
		Tags:                        pulumi.ToStringMap(vpcTags),
		EnableClassiclink:           pulumi.Bool(args.EnableClassiclink),
		EnableClassiclinkDnsSupport: pulumi.Bool(args.EnableClassiclinkDNSSupport),
		EnableDnsHostnames:          pulumi.Bool(args.EnableDNSHostnames),
		EnableDnsSupport:            pulumi.Bool(args.EnableDNSSuport),
		InstanceTenancy:             pulumi.StringPtr(instanceTenancy),
	}

	if args.Ipv6CidrBlock != "" {
		vpcArgs.Ipv6CidrBlock = pulumi.StringPtr(args.Ipv6CidrBlock)
		vpcArgs.Ipv6NetmaskLength = nil
	}

	if args.Ipv4IpamPoolId != "" {
		vpcArgs.Ipv4IpamPoolId = pulumi.StringPtr(args.Ipv4IpamPoolId)
		vpcArgs.Ipv4NetmaskLength = pulumi.IntPtr(args.Ipv4NetmaskLength)
		vpcArgs.CidrBlock = nil
	}

	if args.AssignGeneratedIpv6CidrBlock == true {
		vpcArgs.AssignGeneratedIpv6CidrBlock = pulumi.BoolPtr(args.AssignGeneratedIpv6CidrBlock)
		vpcArgs.Ipv4NetmaskLength = pulumi.IntPtr(args.Ipv6NetmaskLength)
		vpcArgs.Ipv6IpamPoolId = pulumi.StringPtr(args.Ipv6IpamPoolId)
		vpcArgs.Ipv6CidrBlockNetworkBorderGroup = pulumi.StringPtr(args.Ipv6CidrBlockNetworkBorderGroup)
	}

	vpc, err := ec2.NewVpc(ctx, name, vpcArgs, opts...)
	if err != nil {
		return nil, err
	}

	vpcId := vpc.ID()
	vpcChildResourceOptions := []pulumi.ResourceOption{pulumi.Parent(vpc), pulumi.DependsOn([]pulumi.Resource{vpc})}

	igw, err := ec2.NewInternetGateway(ctx, name, &ec2.InternetGatewayArgs{
		VpcId: vpcId,
		Tags: pulumi.ToStringMap(map[string]string{
			"Name": name,
		}),
	}, vpcChildResourceOptions...)
	if err != nil {
		return nil, err
	}

	var vpcEndpoints []*ec2.VpcEndpoint
	var subnets []*ec2.Subnet
	var routeTables []*ec2.RouteTable
	var routeTableAssociations []*ec2.RouteTableAssociation
	var routes []*ec2.Route
	var natGateways []*ec2.NatGateway
	var eips []*ec2.Eip
	var publicSubnetIds []pulumi.IDOutput
	var privateSubnetIds []pulumi.IDOutput
	var isolatedSubnetIds []pulumi.IDOutput

	for _, vpcSubnetSpec := range args.VpcEndpointSpecs {
		vpcEndpoint, err := ec2.NewVpcEndpoint(ctx, vpcSubnetSpec.ServiceName, &ec2.VpcEndpointArgs{
			AutoAccept:        pulumi.BoolPtr(vpcSubnetSpec.AutoAccept),
			Policy:            pulumi.Sprintf("%s", vpcSubnetSpec.Policy),
			PrivateDnsEnabled: pulumi.BoolPtr(vpcSubnetSpec.PrivateDNSEnabled),
			RouteTableIds:     pulumi.ToStringArray(vpcSubnetSpec.RouteTableIds),
			SecurityGroupIds:  pulumi.ToStringArray(vpcSubnetSpec.SecurityGroupIds),
			SubnetIds:         pulumi.ToStringArray(vpcSubnetSpec.SubnetIds),
			Tags:              pulumi.ToStringMap(vpcSubnetSpec.Tags),
			VpcEndpointType:   pulumi.Sprintf("%s", vpcSubnetSpec.VpcEndpointType),
			VpcId:             vpcId,
			ServiceName:       pulumi.Sprintf("%s", vpcSubnetSpec.ServiceName),
		}, vpcChildResourceOptions...)
		if err != nil {
			return nil, err
		}

		vpcEndpoints = append(vpcEndpoints, vpcEndpoint)
	}

	for i, zone := range availabilityZones {
		var specs []subnetSpec
		for _, spec := range subnetSpecs {
			if spec.AzName == zone {
				specs = append(specs, spec)
			}
		}

		sort.SliceStable(specs, compareSubnetSpecs(specs))

		for _, spec := range specs {
			subnet, err := ec2.NewSubnet(ctx, spec.SubnetName, &ec2.SubnetArgs{
				VpcId:               vpcId,
				AvailabilityZone:    pulumi.Sprintf("%s", spec.AzName),
				MapPublicIpOnLaunch: pulumi.BoolPtr(strings.ToLower(spec.Type) == "public"),
				CidrBlock:           pulumi.Sprintf("%s", spec.CidrBlock),
				Tags: pulumi.ToStringMap(map[string]string{
					"Name": spec.SubnetName,
				}),
			}, vpcChildResourceOptions...)
			if err != nil {
				return nil, err
			}

			subnets = append(subnets, subnet)

			switch strings.ToLower(spec.Type) {
			case "public":
				publicSubnetIds = append(publicSubnetIds, subnet.ID())
			case "private":
				privateSubnetIds = append(privateSubnetIds, subnet.ID())
			case "isolated":
				isolatedSubnetIds = append(isolatedSubnetIds, subnet.ID())
			}

			routeTable, err := ec2.NewRouteTable(ctx, spec.SubnetName, &ec2.RouteTableArgs{
				VpcId: vpcId,
				Tags: pulumi.ToStringMap(map[string]string{
					"Name": spec.SubnetName,
				}),
			}, pulumi.Parent(subnet), pulumi.DependsOn([]pulumi.Resource{subnet}))
			if err != nil {
				return nil, err
			}

			routeTables = append(routeTables, routeTable)

			routeTableAssoc, err := ec2.NewRouteTableAssociation(ctx, spec.SubnetName, &ec2.RouteTableAssociationArgs{
				RouteTableId: routeTable.ID(),
				SubnetId:     subnet.ID(),
			}, pulumi.Parent(routeTable), pulumi.DependsOn([]pulumi.Resource{routeTable}))
			if err != nil {
				return nil, err
			}

			routeTableAssociations = append(routeTableAssociations, routeTableAssoc)

			createNatGateway, err := shouldCreateNatGateway(natGatewayStrategy, len(natGateways), i)
			if err != nil {
				return nil, err
			}

			if (strings.ToLower(spec.Type) == "public") && createNatGateway {
				createEip := len(allocationIds) == 0

				var natGatewayAllocationIDs pulumi.StringOutput
				if createEip {
					eipName := fmt.Sprintf("%s-%v", name, i+1)
					eip, err := ec2.NewEip(ctx, eipName, &ec2.EipArgs{}, pulumi.Parent(subnet), pulumi.DependsOn([]pulumi.Resource{subnet}))
					if err != nil {
						return nil, err
					}
					eips = append(eips, eip)

					natGatewayAllocationIDs = eip.AllocationId
				} else {
					natGatewayAllocationIDs = pulumi.String(allocationIds[i]).ToStringOutput()
				}

				natGatewayName := fmt.Sprintf("%s-nat-gateway-%v", name, i+1)
				natGateway, err := ec2.NewNatGateway(ctx, natGatewayName, &ec2.NatGatewayArgs{
					SubnetId:     subnet.ID(),
					AllocationId: natGatewayAllocationIDs,
					Tags: pulumi.ToStringMap(map[string]string{
						"Name": spec.SubnetName,
					}),
				}, pulumi.Parent(subnet), pulumi.DependsOn([]pulumi.Resource{subnet}))
				if err != nil {
					return nil, err
				}

				natGateways = append(natGateways, natGateway)
			}

			switch strings.ToLower(spec.Type) {
			case "public":
				route, err := ec2.NewRoute(ctx, spec.SubnetName, &ec2.RouteArgs{
					RouteTableId:         routeTable.ID(),
					GatewayId:            igw.ID(),
					DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
				}, pulumi.Parent(routeTable), pulumi.DependsOn([]pulumi.Resource{routeTable}))
				if err != nil {
					return nil, err
				}
				routes = append(routes, route)
				break
			case "private":
				var natGatewayID pulumi.IDOutput
				if strings.ToLower(natGatewayStrategy) == "single" {
					natGatewayID = natGateways[0].ID()
				} else {
					natGatewayID = natGateways[i].ID()
				}

				route, err := ec2.NewRoute(ctx, spec.SubnetName, &ec2.RouteArgs{
					RouteTableId:         routeTable.ID(),
					NatGatewayId:         natGatewayID,
					DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
				}, pulumi.Parent(routeTable), pulumi.DependsOn([]pulumi.Resource{routeTable}))
				if err != nil {
					return nil, err
				}
				routes = append(routes, route)
				break
			}
		}
	}

	component.EIPS = eips
	component.InternetGateway = igw
	component.NatGateways = natGateways
	component.RouteTables = routeTables
	component.RouteTableAssociations = routeTableAssociations
	component.Routes = routes
	component.Subnets = subnets
	component.VPC = vpc
	component.VPCEndpoints = vpcEndpoints
	component.VPCID = vpcId
	component.PublicSubnetIDs = pulumi.ToIDArrayOutput(publicSubnetIds)
	component.PrivateSubnetIDs = pulumi.ToIDArrayOutput(privateSubnetIds)
	component.IsolatedSubnetIDs = pulumi.ToIDArrayOutput(isolatedSubnetIds)

	return component, nil
}

func validateNatGatewayStrategy(natGatewayStrategy string, subnets []subnetSpec) error {
	switch strings.ToLower(natGatewayStrategy) {
	case "oneperaz":
	case "single":
		hasPrivate := false
		hasPublic := false
		for _, subnet := range subnets {
			if strings.ToLower(subnet.Type) == "public" {
				hasPublic = true
			}

			if strings.ToLower(subnet.Type) == "private" {
				hasPrivate = true
			}

			if !hasPrivate || !hasPublic {
				return fmt.Errorf("If NAT Gateway strategy is 'OnePerAz' or 'Single', both private and public subnets must be declared. The private subnet creates the need for a NAT Gateway, and the public subnet is required to host the NAT Gateway resource.")
			}
		}
	case "none":
		for _, subnet := range subnets {
			if strings.ToLower(subnet.Type) == "private" {
				return fmt.Errorf("If private subnets are specified, NAT Gateway strategy cannot be 'None'.")
			}
		}
	default:
		return fmt.Errorf("Unknown NAT Gateway strategy %s", natGatewayStrategy)
	}

	return nil
}

func shouldCreateNatGateway(strategy string, numGateways, azIndex int) (bool, error) {
	switch strings.ToLower(strategy) {
	case "none":
		return false, nil
	case "single":
		return numGateways < 1, nil
	case "oneperaz":
		return numGateways < (azIndex + 1), nil
	default:
		return false, fmt.Errorf("Unknown NatGatewayStrategy %s", strategy)
	}
}

func compareSubnetSpecs(specs []subnetSpec) func(x, y int) bool {
	return func(x, y int) bool {
		spec1 := specs[x]
		spec2 := specs[y]

		if spec1.Type == spec2.Type {
			return true
		}

		if strings.ToLower(spec1.Type) == "public" {
			return true
		}

		if (strings.ToLower(spec1.Type) == "private") && (strings.ToLower(spec2.Type) == "public") {
			return false
		}

		if (strings.ToLower(spec1.Type) == "private") && (strings.ToLower(spec2.Type) == "isolated") {
			return true
		}

		return false
	}
}

func validateSubnets(specs []subnetSpec) error {
	overlappingSubnets, err := getOverlappingSubnets(specs)
	if err != nil {
		return err
	}

	if len(overlappingSubnets) > 0 {
		msgParts := []string{
			"The following subnets overlap with at least one other subnet. Make the CIDR for the VPC larger, reduce the size of the subnets per AZ, or use less Availability Zones:\n\n",
		}
		for i, subnet := range overlappingSubnets {
			msgParts = append(msgParts, fmt.Sprintf("%v. %s: %s\n", i+1, subnet.SubnetName, subnet.CidrBlock))
		}

		return fmt.Errorf(strings.Join(msgParts, ""))
	}

	return nil
}

func doSubnetsOverlap(spec1, spec2 subnetSpec) (bool, error) {
	_, ip1, err := net.ParseCIDR(spec1.CidrBlock)
	if err != nil {
		return false, err
	}

	_, ip2, err := net.ParseCIDR(spec2.CidrBlock)
	if err != nil {
		return false, err
	}

	hasOverlap := ip1.Contains(ip2.IP) || ip2.Contains(ip1.IP)
	return hasOverlap, nil
}

func getOverlappingSubnets(specs []subnetSpec) ([]subnetSpec, error) {
	var result []subnetSpec
	for _, x := range specs {
		hasOverlap := false
		for _, y := range specs {
			hasOverlap, err := doSubnetsOverlap(x, y)
			if err != nil {
				return nil, err
			}

			if (x != y) && hasOverlap {
				hasOverlap = true
			}
		}

		if hasOverlap {
			result = append(result, x)
		}
	}

	return result, nil
}

func validateEips(natGatewayStrategy string, eips, availabilityZones []string) error {
	switch strings.ToLower(natGatewayStrategy) {
	case "none":
		if len(eips) > 0 {
			return fmt.Errorf("Elastic IP allocation IDs cannot be specified when NAT Gateway strategy is %s.", natGatewayStrategy)
		}
		break
	case "single":
		if len(eips) > 1 {
			return fmt.Errorf("Exactly one Elastic IP may be specified when NAT Gateway strategy is '%s'.", natGatewayStrategy)
		}
		break
	case "oneperaz":
		if (len(eips) > 0) && (len(eips) != len(availabilityZones)) {
			return fmt.Errorf("The number of Elastic IPs, if specified, must match the number of availability zones for the VPC (%v) when NAT Gateway strategy is '%s'", len(availabilityZones), natGatewayStrategy)
		}
		break
	default:
		return fmt.Errorf("Unknown NatGatewayStrategy '%s'", natGatewayStrategy)
	}

	return nil
}

type subnetSpec struct {
	CidrBlock  string
	Type       string
	AzName     string
	SubnetName string
}

func nextPow2(n int) int {
	if n == 0 {
		return 1
	}

	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16

	return n + 1
}

func ip2BigInt(ip net.IP) *big.Int {
	i := big.NewInt(0)
	i.SetBytes(ip)
	return i
}

func cidrSubnetV4(ipRange string, newBits, netNum int) (string, error) {
	_, ip, err := net.ParseCIDR(ipRange)
	if err != nil {
		return "", fmt.Errorf("Error parsing IP range: %v", err)
	}

	ipSubnetMaskBits, _ := ip.Mask.Size()
	newSubnetMask := ipSubnetMaskBits + newBits
	if newSubnetMask > 32 {
		return "", fmt.Errorf("Requested %v new bits, but only %v are available.", newBits, 32-ipSubnetMaskBits)
	}

	addressBI := ip2BigInt(ip.IP)
	newAddressBase := math.Pow(2, float64(32-newSubnetMask))
	netNumBI := big.NewInt(int64(netNum))

	newAddressBaseBI := big.NewInt(int64(newAddressBase))
	newAddressBI := addressBI.Add(
		addressBI,
		newAddressBaseBI.Mul(newAddressBaseBI, netNumBI),
	)

	newAddress := net.IP(newAddressBI.Bytes())

	return fmt.Sprintf("%s/%v", newAddress.String(), newSubnetMask), nil
}

func generateDefaultSubnets(vpcName, vpcCidr string, azNames, azBases []string) ([]subnetSpec, error) {
	var privateSubnets []subnetSpec
	for i, name := range azNames {
		cidrBlock, err := cidrSubnetV4(azBases[i], 1, 0)
		if err != nil {
			return nil, err
		}

		privateSubnets = append(privateSubnets, subnetSpec{
			AzName:     name,
			Type:       "Private",
			SubnetName: fmt.Sprintf("%s-private-%v", vpcName, i+1),
			CidrBlock:  cidrBlock,
		})
	}

	var publicSubnets []subnetSpec
	for i, name := range azNames {
		splitBase, err := cidrSubnetV4(privateSubnets[i].CidrBlock, 0, 1)
		if err != nil {
			return nil, err
		}

		cidrBlock, err := cidrSubnetV4(splitBase, 1, 0)
		if err != nil {
			return nil, err
		}

		publicSubnets = append(publicSubnets, subnetSpec{
			AzName:     name,
			Type:       "Public",
			SubnetName: fmt.Sprintf("%s-public-%v", vpcName, i+1),
			CidrBlock:  cidrBlock,
		})
	}

	return append(privateSubnets, publicSubnets...), nil
}

func getSubnetSpecs(vpcName, vpcCidr string, azNames []string, subnetInputs []subnetSpecInput) ([]subnetSpec, error) {
	newBitsPerAZ := math.Log2(float64(nextPow2(len(azNames))))

	var azBases []string
	for i, _ := range azNames {
		azBase, err := cidrSubnetV4(vpcCidr, int(newBitsPerAZ), i)
		if err != nil {
			return nil, err
		}
		azBases = append(azBases, azBase)
	}

	if len(subnetInputs) == 0 {
		return generateDefaultSubnets(vpcName, vpcCidr, azNames, azBases)
	}

	_, ip, err := net.ParseCIDR(azBases[0])
	if err != nil {
		return nil, fmt.Errorf("Error parsing IP range for non default VPC: %v", err)
	}

	_, baseSubnetMaskBits := ip.Mask.Size()

	var privateSubnetsIn []subnetSpecInput
	var publicSubnetsIn []subnetSpecInput
	var isolatedSubnetsIn []subnetSpecInput
	for _, subnetIn := range subnetInputs {
		switch strings.ToLower(subnetIn.Type) {
		case "private":
			privateSubnetsIn = append(privateSubnetsIn, subnetIn)
		case "public":
			publicSubnetsIn = append(publicSubnetsIn, subnetIn)
		case "isolated":
			isolatedSubnetsIn = append(isolatedSubnetsIn, subnetIn)
		}
	}

	var subnetOuts []subnetSpec

	for i, name := range azNames {
		var privateSubnetsOut []subnetSpec
		var publicSubnetsOut []subnetSpec
		var isolatedSubnetsOut []subnetSpec

		// Private subnets
		for j, privateIn := range privateSubnetsIn {
			newBits := privateIn.CIDRMask - baseSubnetMaskBits

			privateSubnetCidrBlock, err := cidrSubnetV4(azBases[i], newBits, j)
			if err != nil {
				return nil, err
			}

			privateSubnetsOut = append(privateSubnetsOut, subnetSpec{
				AzName:     name,
				CidrBlock:  privateSubnetCidrBlock,
				Type:       "Private",
				SubnetName: fmt.Sprintf("%s-%s-%v", vpcName, privateIn.Name, i+1),
			})
		}

		// Public Subnets
		for j, publicIn := range publicSubnetsIn {
			baseCidr := azBases[i]
			if len(privateSubnetsOut) > 0 {
				baseCidr = privateSubnetsOut[len(privateSubnetsOut)-1].CidrBlock
			}

			_, baseIP, err := net.ParseCIDR(baseCidr)
			if err != nil {
				return nil, err
			}

			_, basePublicSubnetMaskBits := baseIP.Mask.Size()

			splitBase := azBases[i]
			if len(privateSubnetsOut) > 0 {
				splitBase, err = cidrSubnetV4(baseCidr, 0, 1)
				if err != nil {
					return nil, err
				}
			}

			newPublicSubnetBits := publicIn.CIDRMask - basePublicSubnetMaskBits
			publicSubnetCidrBlock, err := cidrSubnetV4(splitBase, newPublicSubnetBits, j)
			if err != nil {
				return nil, err
			}

			publicSubnetsOut = append(publicSubnetsOut, subnetSpec{
				AzName:     name,
				CidrBlock:  publicSubnetCidrBlock,
				Type:       "Public",
				SubnetName: fmt.Sprintf("%s-%s-%v", vpcName, publicIn.Name, i+1),
			})
		}

		// Isolated Subnets
		for j, isolatedIn := range isolatedSubnetsIn {
			baseCidr := azBases[i]
			if len(publicSubnetsOut) > 0 {
				baseCidr = publicSubnetsOut[len(publicSubnetsOut)-1].CidrBlock
			} else if len(privateSubnetsOut) > 0 {
				baseCidr = privateSubnetsOut[len(privateSubnetsOut)-1].CidrBlock
			}

			_, baseIP, err := net.ParseCIDR(baseCidr)
			if err != nil {
				return nil, err
			}

			_, baseIsolatedSubnetMaskBits := baseIP.Mask.Size()

			splitBase := azBases[i]
			if (len(publicSubnetsOut) > 0) || (len(privateSubnetsOut) > 0) {
				splitBase, err = cidrSubnetV4(baseCidr, 0, 1)
				if err != nil {
					return nil, err
				}
			}

			newIsolatedSubnetBits := isolatedIn.CIDRMask - baseIsolatedSubnetMaskBits
			isolatedSubnetCidrBlock, err := cidrSubnetV4(splitBase, newIsolatedSubnetBits, j)
			isolatedSubnetsOut = append(isolatedSubnetsOut, subnetSpec{
				AzName:     name,
				CidrBlock:  isolatedSubnetCidrBlock,
				Type:       "Isolated",
				SubnetName: fmt.Sprintf("%s-%s-%v", vpcName, isolatedIn.Name, i+1),
			})
		}

		subnetOuts = append(subnetOuts, privateSubnetsOut...)
		subnetOuts = append(subnetOuts, publicSubnetsOut...)
		subnetOuts = append(subnetOuts, isolatedSubnetsOut...)
	}

	return subnetOuts, nil
}
