import json
from types import SimpleNamespace

import jinja2
import pulumi
from pulumi.config import ConfigMissingError
from pulumi.invoke import InvokeOptions
from pulumi.output import Output
from pulumi.resource import ResourceOptions
from pulumi_openstack import compute, dns, networking, sharedfilesystem

from provisioners import ConnectionArgs, CopyFile, CopyFileFromString, RemoteExec


def resources_cache(*names):
    def inner(fn):
        def wrapper(self, *args, **kwargs):
            res = fn(self, *args, **kwargs)
            if len(names) == 1:
                setattr(self.resources, names[0], res)
            else:
                for i in range(len(names)):
                    setattr(self.resources, names[i], res[i])
            return res

        return wrapper

    return inner


class VCFStack:
    def __init__(self, provider_cloud_admin, provider_ccadmin_master) -> None:
        self.config = pulumi.Config()
        self.openstack_config = pulumi.Config("openstack")
        self.stack_name = pulumi.get_stack()
        self.provider_cloud_admin = provider_cloud_admin
        self.provider_ccadmin_master = provider_ccadmin_master

        public_key_file = (
            self.config.get("publicKeyFile") or "/pulumi/automation/etc/.ssh/id_rsa.pub"
        )
        private_key_file = (
            self.config.get("privateKeyFile") or "/pulumi/automation/etc/.ssh/id_rsa"
        )

        try:
            private_networks = json.loads(self.config.require("privateNetworks"))
        except ConfigMissingError:
            private_networks = []
        try:
            esxi_nodes = json.loads(self.config.require("esxiNodes"))
            esxi_image_name = self.config.require("esxiServerImage")
            esxi_flavor_name = self.config.require("esxiServerFlavor")
        except ConfigMissingError:
            esxi_nodes = []
            esxi_image_name = ""
            esxi_flavor_name = ""
        try:
            shares = json.loads(self.config.require("shares"))
        except ConfigMissingError:
            shares = []
        try:
            reserved_ips = json.loads(self.config.require("reservedIPs"))
        except ConfigMissingError:
            reserved_ips = []
        try:
            sddc_manager = json.loads(self.config.require("sddcManager"))
        except ConfigMissingError:
            sddc_manager = {}
        try:
            vcenter = json.loads(self.config.require("vcenter"))
        except ConfigMissingError:
            vcenter = {}
        try:
            nsxt = json.loads(self.config.require("nsxt"))
        except ConfigMissingError:
            nsxt = {}
        try:
            nsxt_managers = json.loads(self.config.require("nsxtManagers"))
        except ConfigMissingError:
            nsxt_managers = []
        try:
            helper_vsanwitness = json.loads(self.config.require("helperVsanWiteness"))
        except ConfigMissingError:
            helper_vsanwitness = None

        self.props = SimpleNamespace(
            helper_vm=json.loads(self.config.require("helperVM")),
            helper_vsanwitness=helper_vsanwitness,
            public_key_file=public_key_file,
            private_key_file=private_key_file,
            nsxt=nsxt,
            nsxt_managers=nsxt_managers,
            sddc_manager=sddc_manager,
            vcenter=vcenter,
            vmware_password=self.config.require("vmwarePassword"),
            # networks
            external_network=json.loads(self.config.require("externalNetwork")),
            mgmt_network=json.loads(self.config.require("managementNetwork")),
            deploy_network=json.loads(self.config.require("deploymentNetwork")),
            public_router_name=self.config.require("publicRouter"),
            private_networks=private_networks,
            # ips and dns names
            dns_zone_name=self.config.require("dnsZoneName"),
            reverse_dns_zone_name=self.config.require("reverseDnsZoneName"),
            reserved_ips=reserved_ips,
            # esxi servers
            esxi_image=esxi_image_name,
            esxi_flavor_name=esxi_flavor_name,
            esxi_nodes=esxi_nodes,
            shares=shares,
        )
        mgmt_network = networking.get_network(name=self.props.mgmt_network["name"])
        mgmt_subnet = networking.get_subnet(name=self.props.mgmt_network["subnet_name"])
        self.resources = SimpleNamespace(
            mgmt_network=mgmt_network,
            mgmt_subnet=mgmt_subnet,
        )
        pulumi.export(
            "ManagementNetwork",
            Output.all(mgmt_network.name, mgmt_network.id).apply(
                lambda args: "{name} ({_id})".format(name=args[0], _id=args[1])
            ),
        )
        pulumi.export(
            "ManagementSubnet",
            Output.all(mgmt_subnet.name, mgmt_subnet.id).apply(
                lambda args: "{name} ({_id})".format(name=args[0], _id=args[1])
            ),
        )

    def provision(self):
        self._provision_keypair()
        self._provision_deployment_network(True)
        self._provision_deployment_subnet(True)
        self._provision_router(True)
        self._provision_helper_vm()
        self._configure_helper_vm()

    @resources_cache("keypair")
    def _provision_keypair(self):
        keypair_name = "rsa_keypair_vcf"
        with open(self.props.public_key_file) as f:
            keypair = compute.Keypair("rsa-keypair-vcf", public_key=f.read())
        pulumi.export("SshKeyPair", keypair.name)
        return keypair

    @resources_cache("deploy_network")
    def _provision_deployment_network(self, protect=False):
        deploy_network = networking.Network(
            self.props.deploy_network["name"],
            opts=ResourceOptions(delete_before_replace=True, protect=protect),
        )
        pulumi.export(
            "DeploymentNetwork",
            Output.all(deploy_network.name, deploy_network.id).apply(
                lambda args: f"{args[0]} ({args[1]})"
            ),
        )
        return deploy_network

    @resources_cache("deploy_subnet")
    def _provision_deployment_subnet(self, protect=False):
        deploy_subnet = networking.Subnet(
            self.props.deploy_network["subnet_name"],
            name=self.props.deploy_network["subnet_name"],
            network_id=self.resources.deploy_network.id,
            cidr=self.props.deploy_network["cidr"],
            ip_version=4,
            opts=ResourceOptions(delete_before_replace=True, protect=protect),
        )
        return deploy_subnet

    def _provision_router(self, protect=False):
        public_router = networking.Router(
            self.props.public_router_name,
            name=self.props.public_router_name,
            external_network_id=self.props.external_network["id"],
            opts=ResourceOptions(delete_before_replace=True, protect=protect),
        )
        networking.RouterInterface(
            "router-interface-management",
            router_id=public_router.id,
            subnet_id=self.resources.mgmt_subnet.id,
            opts=ResourceOptions(
                delete_before_replace=True,
                protect=protect,
            ),
        )
        networking.RouterInterface(
            "router-interface-deployment",
            router_id=public_router.id,
            subnet_id=self.resources.deploy_subnet.id,
            opts=ResourceOptions(
                delete_before_replace=True,
                protect=protect,
            ),
        )
        pulumi.export(
            "PublicRouter",
            Output.all(public_router.name, public_router.id).apply(
                lambda args: f"{args[0]} ({args[1]})"
            ),
        )

    @resources_cache("helper_vm", "attach_external_ip_helper_vm")
    def _provision_helper_vm(self):
        init_script = r"""#!/bin/bash
echo 'net.ipv4.conf.default.rp_filter = 2' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.rp_filter = 2' >> /etc/sysctl.conf
/usr/sbin/sysctl -p /etc/sysctl.conf
"""
        sg = compute.SecGroup(
            "helper-vm-sg",
            description="allow ssh",
            rules=[
                compute.SecGroupRuleArgs(
                    cidr="0.0.0.0/0", from_port=22, to_port=22, ip_protocol="tcp"
                )
            ],
        )
        external_port = networking.Port(
            "helper-vm-external-port",
            network_id=self.resources.mgmt_network.id,
            fixed_ips=[
                networking.PortFixedIpArgs(
                    subnet_id=self.resources.mgmt_subnet.id,
                    ip_address=self.props.helper_vm["ip"],
                )
            ],
            security_group_ids=[sg.id],
        )
        helper_vm = compute.Instance(
            "helper-vm",
            name="helper-vm",
            flavor_name=self.props.helper_vm["flavor_name"],
            image_name=self.props.helper_vm["image_name"],
            networks=[
                compute.InstanceNetworkArgs(name=self.resources.deploy_network.name),
            ],
            key_pair=self.resources.keypair.name,
            user_data=init_script,
            opts=ResourceOptions(
                delete_before_replace=True,
                ignore_changes=["image_name", "key_pair"],
            ),
        )
        attach_external_ip = compute.InterfaceAttach(
            "helper-vm-attatch",
            instance_id=helper_vm.id,
            port_id=external_port.id,
            opts=ResourceOptions(delete_before_replace=True, depends_on=[helper_vm]),
        )
        pulumi.export(
            "HelperVM",
            Output.all(
                helper_vm.name, helper_vm.id, external_port.all_fixed_ips[0]
            ).apply(lambda args: f"{args[0]} ({args[1]}, {args[2]})"),
        )
        return helper_vm, attach_external_ip

    @resources_cache("copy_config_sh")
    def _configure_helper_vm(self):
        conn_args = ConnectionArgs(
            host=self.props.helper_vm["ip"],
            username="ccloud",
            private_key_file=self.props.private_key_file,
        )
        exec_install_pwsh = RemoteExec(
            "install-powershell",
            host_id=self.resources.helper_vm.id,
            conn=conn_args,
            commands=[
                "[ ! -f packages-microsoft-prod.deb ] && wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb || true",
                "sudo dpkg -i packages-microsoft-prod.deb",
                "sudo apt-get update",
                "echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections",
                "sudo apt-get install -y -q powershell",
                "pwsh -Command Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted",
                "pwsh -Command Install-Module VMware.PowerCLI",
                "pwsh -Command Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:0",
                "pwsh -Command Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP 0 -Confirm:0",
            ],
            opts=ResourceOptions(
                depends_on=[self.resources.attach_external_ip_helper_vm]
            ),
        )

        # copy rsa key
        copy_rsa_key = CopyFile(
            "copy-rsa-key",
            host_id=self.resources.helper_vm.id,
            conn=conn_args,
            src=self.props.private_key_file,
            dest="/home/ccloud/esxi_rsa",
            mode="600",
            opts=ResourceOptions(depends_on=[exec_install_pwsh]),
        )

        with open("./scripts/cleanup.sh") as f:
            template = jinja2.Template(f.read())
            cleanup_script = template.render(
                vmware_password=self.props.vmware_password,
            )
            copy_cleanup_sh = CopyFileFromString(
                "copy-cleanup-sh",
                host_id=self.resources.helper_vm.id,
                conn=conn_args,
                from_str=cleanup_script,
                dest="/home/ccloud/cleanup.sh",
                opts=ResourceOptions(depends_on=[copy_rsa_key]),
            )
        with open("./scripts/config.sh") as f:
            template = jinja2.Template(f.read())
            config_script = template.render(
                management_network=self.props.mgmt_network,
                vmware_password=self.props.vmware_password,
            )
            copy_config_sh = CopyFileFromString(
                "copy-config-sh",
                host_id=self.resources.helper_vm.id,
                conn=conn_args,
                from_str=config_script,
                dest="/home/ccloud/config.sh",
                opts=ResourceOptions(depends_on=[copy_cleanup_sh]),
            )
        return copy_config_sh

    def _provision_vsanwiteness_helper(self):
        props = self.props.helper_vsanwitness
        compute.Instance(
            "helper-vsanwitness",
            name="helper-vsanwitness",
            flavor_name=props["flavor_name"],
            image_name=props["image_name"],
            availability_zone=props["availability_zone"],
            networks=[
                compute.InstanceNetworkArgs(name=self.resources.deploy_network.name),
                compute.InstanceNetworkArgs(
                    name=self.resources.private_networks["vsanwitness"]["network"].name
                ),
            ],
            key_pair=self.resources.keypair.name,
            opts=ResourceOptions(
                delete_before_replace=True,
                ignore_changes=["image_name", "key_pair"],
            ),
        )

    @resources_cache("private_router")
    def _provision_private_router(self):
        return networking.Router(
            "mgmtdomain-private-router",
            name="mgmtdomain-private-router-" + self.stack_name,
            opts=ResourceOptions(delete_before_replace=True),
        )

    @resources_cache("private_networks")
    def _provision_private_networks(self):
        """ private networks """
        private_networks = {}
        for props in self.props.private_networks:
            network = networking.Network("private-network-" + props["name"])
            subnet = networking.Subnet(
                "subnet-" + props["name"],
                network_id=network.id,
                cidr=props["cidr"],
                ip_version=4,
                opts=ResourceOptions(delete_before_replace=True),
            )
            networking.RouterInterface(
                "router-interface-" + props["name"],
                router_id=self.resources.private_router.id,
                subnet_id=subnet.id,
                opts=ResourceOptions(delete_before_replace=True),
            )
            private_networks[props["name"]] = {
                "network": network,
                "subnet": subnet,
                "vlan_id": props["vlan_id"],
            }
        return private_networks

    @resources_cache("esxi_servers")
    def _provision_esxi_servers(self):
        """ esxi installation """
        esxi_servers = []

        for n in self.props.esxi_nodes:

            if "flavor" in n.keys():
                node_flavor = n["flavor"]
            else:
                node_flavor = self.props.esxi_flavor_name

            node_name, node_id, node_ip = n["name"], n["id"], n["ip"]

            parent_port = networking.Port(
                node_name + "-deployment",
                network_id=self.resources.deploy_network.id,
            )

            instance = compute.Instance(
                "esxi-" + node_name,
                name="esxi-" + node_name,
                availability_zone_hints=f"::{node_id}",
                flavor_name=node_flavor,
                image_name=self.props.esxi_image,
                networks=[compute.InstanceNetworkArgs(port=parent_port.id)],
                key_pair=self.resources.keypair.name,
                opts=ResourceOptions(
                    delete_before_replace=True,
                    ignore_changes=["image_name", "key_pair"],
                ),
            )
            esxi_servers.append(
                {
                    "node_name": node_name,
                    "node_id": node_id,
                    "node_ip": node_ip,
                    "server": instance,
                }
            )

            subport_vmotion = networking.Port(
                node_name + "-vmotion",
                admin_state_up=True,
                network_id=self.resources.private_networks["vmotion"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[self.resources.private_networks["vmotion"]["subnet"]]
                ),
            )
            subport_edgetep = networking.Port(
                node_name + "-edgetep",
                network_id=self.resources.private_networks["edgetep"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[self.resources.private_networks["edgetep"]["subnet"]]
                ),
            )
            subport_hosttep = networking.Port(
                node_name + "-hosttep",
                network_id=self.resources.private_networks["hosttep"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[self.resources.private_networks["hosttep"]["subnet"]]
                ),
            )
            subport_nfs = networking.Port(
                node_name + "-nfs",
                network_id=self.resources.private_networks["nfs"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[self.resources.private_networks["nfs"]["subnet"]]
                ),
            )
            subport_vsan = networking.Port(
                node_name + "-vsan",
                network_id=self.resources.private_networks["vsan"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[self.resources.private_networks["vsan"]["subnet"]]
                ),
            )
            subport_vsanwitness = networking.Port(
                node_name + "-vsanwitness",
                network_id=self.resources.private_networks["vsanwitness"]["network"].id,
                opts=ResourceOptions(
                    depends_on=[
                        self.resources.private_networks["vsanwitness"]["subnet"]
                    ]
                ),
            )
            subport_management = networking.Port(
                node_name + "-management-vcf01",
                network_id=self.resources.mgmt_network.id,
                fixed_ips=[
                    networking.PortFixedIpArgs(
                        subnet_id=self.resources.mgmt_subnet.id, ip_address=node_ip
                    )
                ],
            )
            pn = self.resources.private_networks
            trunk = networking.trunk.Trunk(
                node_name + "-trunk",
                name=node_name + "-trunk",
                admin_state_up=True,
                port_id=parent_port.id,
                sub_ports=[
                    networking.TrunkSubPortArgs(
                        port_id=subport_vmotion.id,
                        segmentation_id=pn["vmotion"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_edgetep.id,
                        segmentation_id=pn["edgetep"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_hosttep.id,
                        segmentation_id=pn["hosttep"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_nfs.id,
                        segmentation_id=pn["nfs"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_vsan.id,
                        segmentation_id=pn["vsan"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_vsanwitness.id,
                        segmentation_id=pn["vsanwitness"]["vlan_id"],
                        segmentation_type="vlan",
                    ),
                    networking.TrunkSubPortArgs(
                        port_id=subport_management.id,
                        segmentation_id=self.props.mgmt_network["vlan_id"],
                        segmentation_type="vlan",
                    ),
                ],
                opts=ResourceOptions(depends_on=[instance]),
            )

            pulumi.export(node_name + "_port_vmotion", subport_vmotion.name)
            pulumi.export(node_name + "_port_edgetep", subport_edgetep.name)
            pulumi.export(node_name + "_port_hosttep", subport_hosttep.name)
            pulumi.export(node_name + "_port_nfs", subport_nfs.name)
            pulumi.export(node_name + "_port_vsan", subport_vsan.name)
            pulumi.export(node_name + "_port_vsanwiteness", subport_vsanwitness.name)

        return esxi_servers

    def _configure_esxi_server(self, esxi_server):
        server, node_name, node_ip = (
            esxi_server["server"],
            esxi_server["node_name"],
            esxi_server["node_ip"],
        )
        # set password
        command_set_passwd = server.access_ip_v4.apply(
            lambda local_ip: (
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "
                "-i /home/ccloud/esxi_rsa root@{0} 'echo {1} | passwd --stdin root'"
            ).format(local_ip, self.props.vmware_password)
        )
        # config node
        command_config = server.access_ip_v4.apply(
            lambda local_ip: "pwsh /home/ccloud/config.sh -LocalIP {} -IP {} -Gateway {} -Netmask {}".format(
                local_ip,
                node_ip,
                self.props.mgmt_network["subnet_gateway"],
                self.props.mgmt_network["subnet_mask"],
            )
        )
        # remove vmk0
        command_cleanup = "pwsh /home/ccloud/cleanup.sh -HostIP {}".format(node_ip)

        # connection
        conn_helper_args = ConnectionArgs(
            host=self.props.helper_vm["ip"],
            username="ccloud",
            private_key_file=self.props.private_key_file,
        )
        conn_esxi_args = ConnectionArgs(
            host=node_ip,
            username="root",
            private_key_file=self.props.private_key_file,
        )

        # execution
        step_1 = RemoteExec(
            "configure-" + node_name + "-step-1",
            host_id=server.id,
            conn=conn_helper_args,
            commands=[command_set_passwd],
            opts=ResourceOptions(depends_on=[self.resources.copy_config_sh]),
        )
        step_2 = RemoteExec(
            "configure-" + node_name + "-step-2",
            host_id=server.id,
            conn=conn_helper_args,
            commands=[command_config],
            opts=ResourceOptions(depends_on=[step_1]),
        )
        step_3 = RemoteExec(
            "configure-" + node_name + "-step-3",
            host_id=server.id,
            conn=conn_esxi_args,
            commands=[
                "/sbin/generate-certificates",
                "/etc/init.d/hostd restart",
                "/etc/init.d/vpxa restart",
            ],
            opts=ResourceOptions(depends_on=[step_2]),
        )
        step_4 = RemoteExec(
            "configure-" + node_name + "-step-4",
            host_id=server.id,
            conn=conn_helper_args,
            commands=[command_cleanup],
            opts=ResourceOptions(depends_on=[step_3]),
        )

    def _provision_dns_record(self, dns_name, ipaddr):
        dns_zone = dns.get_dns_zone(name=self.props.dns_zone_name)
        reverse_dns_zone = dns.get_dns_zone(
            name=self.props.reverse_dns_zone_name,
            # opts=InvokeOptions(provider=self.provider_ccadmin_master),
        )
        dns_name = dns_name + "." + self.props.dns_zone_name
        r = dns.RecordSet(
            dns_name,
            name=dns_name,
            records=[ipaddr],
            type="A",
            ttl=1800,
            zone_id=dns_zone.id,
            opts=ResourceOptions(delete_before_replace=True),
        )
        dns.RecordSet(
            "reverse-" + dns_name,
            name=ipaddr.split(".")[-1] + "." + self.props.reverse_dns_zone_name,
            records=[dns_name],
            type="PTR",
            ttl=1800,
            zone_id=reverse_dns_zone.id,
            opts=ResourceOptions(
                # provider=self.provider_ccadmin_master,
                delete_before_replace=True,
                depends_on=[r],
            ),
        )

    def _provision_reserved_names(self):
        for r in self.props.reserved_ips:
            ipaddr, hostname = r["ip"], r["hostname"]
            self._provision_dns_record(hostname, ipaddr)
            networking.Port(
                "reserved-port-" + ipaddr,
                network_id=self.resources.mgmt_network.id,
                fixed_ips=[
                    networking.PortFixedIpArgs(
                        subnet_id=self.resources.mgmt_subnet.id,
                        ip_address=ipaddr,
                    )
                ],
                opts=ResourceOptions(delete_before_replace=True),
            )

    def _provision_esxi_dns_recrods(self):
        for n in self.props.esxi_nodes:
            node_name, node_ip = n["name"], n["ip"]
            self._provision_dns_record("esxi-" + node_name, node_ip)

    def _provision_shares(self):
        try:
            nfs_network = self.resources.private_networks["nfs"]["network"]
            nfs_subnet = self.resources.private_networks["nfs"]["subnet"]
        except KeyError:
            return
        share_network = sharedfilesystem.ShareNetwork(
            "share_network_vcf",
            description="share network for vcf datastore",
            neutron_net_id=nfs_network.id,
            neutron_subnet_id=nfs_subnet.id,
        )
        for ss in self.props.shares:
            share_name, share_size, az = (
                ss["share_name"],
                ss["share_size"],
                ss["availability_zone"],
            )
            sharedfilesystem.Share(
                share_name,
                name=share_name,
                share_network_id=share_network.id,
                share_proto="NFS",
                size=share_size,
                availability_zone=az,
            )

    def _gen_cloud_builder_json(self):
        with open("./scripts/cloud-builder.json.tpl") as f:
            template = jinja2.Template(f.read())
            cbj = template.render(
                esxi_servers=self.props.esxi_nodes,
                management_network=self.props.mgmt_network,
                nsxt=self.props.nsxt,
                nsxt_managers=self.props.nsxt_managers,
                sddc_manager=self.props.sddc_manager,
                vcenter=self.props.vcenter,
                vmware_password=self.props.vmware_password,
                region=self.openstack_config.require("region"),
            )
            pulumi.export("cloud-builder", cbj)
