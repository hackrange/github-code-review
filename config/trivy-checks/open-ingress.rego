# METADATA
# title: Security group allows ingress from any address on a port that is not the web
# description: |-
#   A security group rule that accepts 0.0.0.0/0 on a port nobody browses to.
#
#   The engine ships a rule for this and it covers SSH and RDP only, so an
#   ingress from the whole internet to 8080, or to a database port, or to a
#   cache, produces nothing at all.  On one repository that was the single
#   most serious thing another scanner found and this one reported no
#   security group rule of any kind.
#
#   80 and 443 are deliberately not flagged.  A public web application is
#   reachable from the internet on purpose, and a rule that says so on every
#   load balancer in an estate is a rule people learn to skip, which costs
#   more than it finds.  Everything else open to everybody is worth a look:
#   it is either a database somebody exposed or an application port that was
#   meant to sit behind the load balancer.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCR-0001
#   avd_id: GCR-0001
#   severity: HIGH
#   short_code: no-public-ingress-non-web
#   recommended_action: Restrict the source range, or move the port behind a load balancer.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
package gcr.aws.ec2.gcr0001

import rego.v1

# The ports a public application is expected to answer on.  Anything here is
# not reported: being on the internet is what these are for.
web_ports := {80, 443}

open_cidr(rule) if {
	some cidr in rule.cidrs
	cidr.value in {"0.0.0.0/0", "::/0"}
}

# A rule that covers a port range containing something other than the web
# ports.  Written as "is there any port in the range that is not web" so a
# range of 0 to 65535 is caught rather than skipped for containing 443.
non_web_port(rule) if {
	rule.fromport.value != rule.toport.value
}

non_web_port(rule) if {
	rule.fromport.value == rule.toport.value
	not rule.fromport.value in web_ports
}

deny contains res if {
	some group in input.aws.ec2.securitygroups
	some rule in group.ingressrules
	open_cidr(rule)
	non_web_port(rule)
	res := result.new(
		sprintf("Security group accepts traffic from any address on port %d, which is not a web port.", [rule.fromport.value]),
		rule,
	)
}
