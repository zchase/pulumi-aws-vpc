import * as vpc from "@pulumi/aws-vpc";

export const myVpc = new vpc.Vpc("zchase-cool-vpc");
