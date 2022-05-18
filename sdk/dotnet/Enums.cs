// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.ComponentModel;
using Pulumi;

namespace Pulumi.AwsVpc
{
    /// <summary>
    /// A strategy for creating NAT Gateways for private subnets within a VPC.
    /// </summary>
    [EnumType]
    public readonly struct NatGatewayStrategy : IEquatable<NatGatewayStrategy>
    {
        private readonly string _value;

        private NatGatewayStrategy(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Do not create any NAT Gateways. Resources in private subnets will not be able to access the internet.
        /// </summary>
        public static NatGatewayStrategy None { get; } = new NatGatewayStrategy("None");
        /// <summary>
        /// Create a single NAT Gateway for the entire VPC. This configuration is not recommended for production infrastructure as it creates a single point of failure.
        /// </summary>
        public static NatGatewayStrategy Single { get; } = new NatGatewayStrategy("Single");
        /// <summary>
        /// Create a NAT Gateway in each availability zone. This is the recommended configuration for production infrastructure.
        /// </summary>
        public static NatGatewayStrategy OnePerAz { get; } = new NatGatewayStrategy("OnePerAz");

        public static bool operator ==(NatGatewayStrategy left, NatGatewayStrategy right) => left.Equals(right);
        public static bool operator !=(NatGatewayStrategy left, NatGatewayStrategy right) => !left.Equals(right);

        public static explicit operator string(NatGatewayStrategy value) => value._value;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => obj is NatGatewayStrategy other && Equals(other);
        public bool Equals(NatGatewayStrategy other) => string.Equals(_value, other._value, StringComparison.Ordinal);

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value?.GetHashCode() ?? 0;

        public override string ToString() => _value;
    }

    /// <summary>
    /// A type of subnet within a VPC.
    /// </summary>
    [EnumType]
    public readonly struct SubnetType : IEquatable<SubnetType>
    {
        private readonly string _value;

        private SubnetType(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// A subnet whose hosts can directly communicate with the internet.
        /// </summary>
        public static SubnetType Public { get; } = new SubnetType("Public");
        /// <summary>
        /// A subnet whose hosts can not directly communicate with the internet, but can initiate outbound network traffic via a NAT Gateway.
        /// </summary>
        public static SubnetType Private { get; } = new SubnetType("Private");
        /// <summary>
        /// A subnet whose hosts have no connectivity with the internet.
        /// </summary>
        public static SubnetType Isolated { get; } = new SubnetType("Isolated");

        public static bool operator ==(SubnetType left, SubnetType right) => left.Equals(right);
        public static bool operator !=(SubnetType left, SubnetType right) => !left.Equals(right);

        public static explicit operator string(SubnetType value) => value._value;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => obj is SubnetType other && Equals(other);
        public bool Equals(SubnetType other) => string.Equals(_value, other._value, StringComparison.Ordinal);

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => _value?.GetHashCode() ?? 0;

        public override string ToString() => _value;
    }
}
