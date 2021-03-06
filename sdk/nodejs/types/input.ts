// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs, enums } from "../types";

/**
 * Configuration for a VPC subnet.
 */
export interface SubnetSpecArgs {
    /**
     * The bitmask for the subnet's CIDR block.
     */
    cidrMask: number;
    /**
     * The subnet's name. Will be templated upon creation.
     */
    name?: string;
    /**
     * The type of subnet.
     */
    type: enums.SubnetType;
}

export interface VpcEndpointSpecArgs {
    /**
     * Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
     */
    autoAccept?: boolean;
    /**
     * A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
     */
    policy?: pulumi.Input<string>;
    /**
     * Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
     */
    privateDnsEnabled?: boolean;
    /**
     * One or more route table IDs. Applicable for endpoints of type `Gateway`.
     */
    routeTableIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
     * If no security groups are specified, the VPC's [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
     */
    securityGroupIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The service name. For AWS services the service name is usually in the form `com.amazonaws.<region>.<service>` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.<region>.notebook`).
     */
    serviceName: string;
    /**
     * The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`.
     */
    subnetIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
     */
    tags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
     */
    vpcEndpointType?: pulumi.Input<string>;
}
