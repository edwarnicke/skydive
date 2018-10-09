/*
 * Copyright (C) 2018 Orange.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package jsonof

import (
	"fmt"
	"strings"
	"testing"
)

var testScans = []struct {
	name     string
	openflow string
	tokens   []Token
}{
	{
		"default",
		" cookie=0x0, duration=337052.111s, table=0, n_packets=0, n_bytes=0, priority=0 actions=NORMAL",
		[]Token{
			tSpace, tText, tEqual, tText, tComma, tSpace, tText, tEqual, tText, tComma, tSpace,
			tText, tEqual, tText, tComma, tSpace, tText, tEqual, tText, tComma, tSpace,
			tText, tEqual, tText, tComma, tSpace, tText, tEqual, tText, tSpace,
			tText, tEqual, tText, tEOF,
		},
	},
	{
		"long rule",
		" cookie=0x20, duration=57227.249s, table=21, priority=1,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop",
		[]Token{
			tSpace, tText, tEqual, tText, tComma, tSpace,
			tText, tEqual, tText, tComma, tSpace,
			tText, tEqual, tText, tComma, tSpace,
			tText, tEqual, tText, tComma, tText, tEqual, tText,
			tSpace, tText, tEqual, tText, tEOF,
		},
	},
}

var testParses = []struct {
	name     string
	openflow string
	json     string
}{
	{
		"controller action",
		" cookie=0x1, duration=1.11s, table=11, n_packets=1, n_bytes=1, priority=11,icmp1,metadata=0x1,ipv1_dst=fe11::11:1ff:fe11:11,nw_ttl=11,icmp_type=11,icmp_code=1,nd_target=fe11::11:1ff:fe11:11 actions=controller(userdata=11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11)",
		`{"cookie":1,"table":11,"priority":11,"meta":[{"k":"duration","v":"1.11s"},{"k":"n_packets","v":"1"},{"k":"n_bytes","v":"1"}],"filters":[{"k":"icmp1","v":""},{"k":"metadata","v":"0x1"},{"k":"ipv1_dst","v":"fe11::11:1ff:fe11:11"},{"k":"nw_ttl","v":"11"},{"k":"icmp_type","v":"11"},{"k":"icmp_code","v":"1"},{"k":"nd_target","v":"fe11::11:1ff:fe11:11"}],"actions":[{"f":"controller","a":[{"f":"11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11.11","k":"userdata"}]}]}`,
	},
	{
		"mac address field",
		" cookie=0x1, duration=1.11s, table=11, n_packets=1, n_bytes=1, priority=11,icmp1,reg11=0x1,metadata=0x1,dl_src=f1:11:11:11:11:11,nw_ttl=11,icmp_type=11,icmp_code=1,nd_sll=11:11:11:11:11:11 actions=resubmit(,11)",
		`{"cookie":1,"table":11,"priority":11,"meta":[{"k":"duration","v":"1.11s"},{"k":"n_packets","v":"1"},{"k":"n_bytes","v":"1"}],"filters":[{"k":"icmp1","v":""},{"k":"reg11","v":"0x1"},{"k":"metadata","v":"0x1"},{"k":"dl_src","v":"f1:11:11:11:11:11"},{"k":"nw_ttl","v":"11"},{"k":"icmp_type","v":"11"},{"k":"icmp_code","v":"1"},{"k":"nd_sll","v":"11:11:11:11:11:11"}],"actions":[{"f":"resubmit","a":[null,{"f":"11"}]}]}`,
	},
	{
		"ip v6 field",
		" cookie=0x1, duration=1.11s, table=11, n_packets=1, n_bytes=1, priority=11,icmp1,reg11=0x1,metadata=0x1,ipv1_dst=ff11::1:ff11:11,nw_ttl=11,icmp_type=11,icmp_code=1,nd_target=fe11::11:1ff:fe11:11 actions=resubmit(,11)",
		`{"cookie":1,"table":11,"priority":11,"meta":[{"k":"duration","v":"1.11s"},{"k":"n_packets","v":"1"},{"k":"n_bytes","v":"1"}],"filters":[{"k":"icmp1","v":""},{"k":"reg11","v":"0x1"},{"k":"metadata","v":"0x1"},{"k":"ipv1_dst","v":"ff11::1:ff11:11"},{"k":"nw_ttl","v":"11"},{"k":"icmp_type","v":"11"},{"k":"icmp_code","v":"1"},{"k":"nd_target","v":"fe11::11:1ff:fe11:11"}],"actions":[{"f":"resubmit","a":[null,{"f":"11"}]}]}`,
	},
	{
		"learn action",
		" cookie=0x0, duration=0.009s, table=0, n_packets=0, n_bytes=0, reset_counts actions=learn(table=1,hard_timeout=60,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),resubmit(,1)",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.009s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":null,"actions":[{"f":"learn","a":[{"f":"1","k":"table"},{"f":"60","k":"hard_timeout"},{"f":"range","a":[{"f":"NXM_OF_VLAN_TCI"},{"f":"0"},{"f":"11"}]},{"f":"=","a":[{"f":"range","a":[{"f":"NXM_OF_ETH_DST"}]},{"f":"range","a":[{"f":"NXM_OF_ETH_SRC"}]}]},{"f":"output","a":[{"f":"range","a":[{"f":"NXM_OF_IN_PORT"}]}]}]},{"f":"resubmit","a":[null,{"f":"1"}]}]}`,
	},
	{
		"move action",
		" cookie=0xd, duration=0.412s, table=0, n_packets=0, n_bytes=0, reset_counts dl_src=60:66:66:66:00:03 actions=pop_mpls:0x0800,move:NXM_OF_IP_DST[]->NXM_OF_IP_SRC[],CONTROLLER:65535",
		`{"cookie":13,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.412s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"dl_src","v":"60:66:66:66:00:03"}],"actions":[{"f":"pop_mpls","a":[{"f":"0x0800"}]},{"f":"move","a":[{"f":"range","a":[{"f":"NXM_OF_IP_DST"}]},{"f":"range","a":[{"f":"NXM_OF_IP_SRC"}]}]},{"f":"CONTROLLER","a":[{"f":"65535"}]}]}`,
	},
	{
		"push/pop actions",
		" cookie=0xd, duration=0.412s, table=0, n_packets=0, n_bytes=0, reset_counts dl_src=60:66:66:66:00:04 actions=pop_mpls:0x0800,push:NXM_OF_IP_DST[],pop:NXM_OF_IP_SRC[],CONTROLLER:65535",
		`{"cookie":13,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.412s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"dl_src","v":"60:66:66:66:00:04"}],"actions":[{"f":"pop_mpls","a":[{"f":"0x0800"}]},{"f":"push","a":[{"f":"range","a":[{"f":"NXM_OF_IP_DST"}]}]},{"f":"pop","a":[{"f":"range","a":[{"f":"NXM_OF_IP_SRC"}]}]},{"f":"CONTROLLER","a":[{"f":"65535"}]}]}`,
	},
	{
		"set_field action",
		" cookie=0xa, duration=0.414s, table=0, n_packets=1, n_bytes=42, reset_counts dl_src=40:44:44:44:44:42 actions=push_mpls:0x8847,set_field:10/0xfffff->mpls_label,set_field:3/0x7->mpls_tc,set_field:10.0.0.1->ip_dst,CONTROLLER:65535",
		`{"cookie":10,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.414s"},{"k":"n_packets","v":"1"},{"k":"n_bytes","v":"42"},{"k":"reset_counts","v":""}],"filters":[{"k":"dl_src","v":"40:44:44:44:44:42"}],"actions":[{"f":"push_mpls","a":[{"f":"0x8847"}]},{"f":"set_field","a":[{"f":"10"},{"f":"0xfffff"},{"f":"mpls_label"}]},{"f":"set_field","a":[{"f":"3"},{"f":"0x7"},{"f":"mpls_tc"}]},{"f":"set_field","a":[{"f":"10.0.0.1"},null,{"f":"ip_dst"}]},{"f":"CONTROLLER","a":[{"f":"65535"}]}]}`,
	},
	{
		"bundle_load action",
		" cookie=0xd, duration=97.230s, table=0, n_packets=3, n_bytes=186, reset_counts dl_src=60:66:66:66:00:06 actions=pop_mpls:0x0800,bundle_load(eth_src,50,hrw,ofport,NXM_OF_IP_SRC[0..15],slaves:1,2),CONTROLLER:65535",
		`{"cookie":13,"table":0,"priority":0,"meta":[{"k":"duration","v":"97.230s"},{"k":"n_packets","v":"3"},{"k":"n_bytes","v":"186"},{"k":"reset_counts","v":""}],"filters":[{"k":"dl_src","v":"60:66:66:66:00:06"}],"actions":[{"f":"pop_mpls","a":[{"f":"0x0800"}]},{"f":"bundle_load","a":[{"f":"eth_src"},{"f":"50"},{"f":"hrw"},{"f":"ofport"},{"f":"range","a":[{"f":"NXM_OF_IP_SRC"},{"f":"0"},{"f":"15"}]},{"f":"slaves","a":[{"f":"1"}]},{"f":"2"}]},{"f":"CONTROLLER","a":[{"f":"65535"}]}]}`,
	},
	{
		"load action",
		" cookie=0x0, duration=0.018s, table=0, n_packets=0, n_bytes=0, reset_counts priority=100,in_port=1 actions=load:0x1->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x3->NXM_NX_REG12[],load:0x1->OXM_OF_METADATA[],load:0x1->NXM_NX_REG14[],resubmit(,8)",
		`{"cookie":0,"table":0,"priority":100,"meta":[{"k":"duration","v":"0.018s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"in_port","v":"1"}],"actions":[{"f":"load","a":[{"f":"0x1"},{"f":"range","a":[{"f":"NXM_NX_REG13"}]}]},{"f":"load","a":[{"f":"0x2"},{"f":"range","a":[{"f":"NXM_NX_REG11"}]}]},{"f":"load","a":[{"f":"0x3"},{"f":"range","a":[{"f":"NXM_NX_REG12"}]}]},{"f":"load","a":[{"f":"0x1"},{"f":"range","a":[{"f":"OXM_OF_METADATA"}]}]},{"f":"load","a":[{"f":"0x1"},{"f":"range","a":[{"f":"NXM_NX_REG14"}]}]},{"f":"resubmit","a":[null,{"f":"8"}]}]}`,
	},
	{
		"encap",
		" cookie=0x0, duration=0.007s, table=0, n_packets=0, n_bytes=0, ip,in_port=1 actions=encap(nsh(md_type=2,tlv(0x1000,10,0x12345678),tlv(0x2000,20,0xfedcba9876543210))),set_field:0x1234->nsh_spi,encap(ethernet),set_field:11:22:33:44:55:66->eth_dst,output:3",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.007s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"}],"filters":[{"k":"ip","v":""},{"k":"in_port","v":"1"}],"actions":[{"f":"encap","a":[{"f":"nsh","a":[{"f":"2","k":"md_type"},{"f":"tlv","a":[{"f":"0x1000"},{"f":"10"},{"f":"0x12345678"}]},{"f":"tlv","a":[{"f":"0x2000"},{"f":"20"},{"f":"0xfedcba9876543210"}]}]}]},{"f":"set_field","a":[{"f":"0x1234"},null,{"f":"nsh_spi"}]},{"f":"encap","a":[{"f":"ethernet"}]},{"f":"set_field","a":[{"f":"11:22:33:44:55:66"},null,{"f":"eth_dst"}]},{"f":"output","a":[{"f":"3"}]}]}`,
	},
	{
		"ct action",
		" cookie=0x0, duration=0.007s, table=5, n_packets=0, n_bytes=0, reset_counts priority=10,ct_state=+new-rel,ip,reg2=0x1 actions=ct(commit,zone=NXM_NX_REG4[0..15],exec(move:NXM_NX_REG3[]->NXM_NX_CT_MARK[],move:NXM_NX_REG1[]->NXM_NX_CT_LABEL[96..127])),resubmit(,6)",
		`{"cookie":0,"table":5,"priority":10,"meta":[{"k":"duration","v":"0.007s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"ct_state","v":"+new-rel"},{"k":"ip","v":""},{"k":"reg2","v":"0x1"}],"actions":[{"f":"ct","a":[{"f":"commit"},{"f":"range","a":[{"f":"NXM_NX_REG4"},{"f":"0"},{"f":"15"}],"k":"zone"},{"f":"exec","a":[{"f":"move","a":[{"f":"range","a":[{"f":"NXM_NX_REG3"}]},{"f":"range","a":[{"f":"NXM_NX_CT_MARK"}]}]},{"f":"move","a":[{"f":"range","a":[{"f":"NXM_NX_REG1"}]},{"f":"range","a":[{"f":"NXM_NX_CT_LABEL"},{"f":"96"},{"f":"127"}]}]}]}]},{"f":"resubmit","a":[null,{"f":"6"}]}]}`,
	},
	{
		"sample action",
		" cookie=0x0, duration=0.007s, table=0, n_packets=0, n_bytes=0, reset_counts in_port=3 actions=sample(probability=65535,collector_set_id=1,obs_domain_id=0,obs_point_id=0,sampling_port=1),output:1,sample(probability=65535,collector_set_id=1,obs_domain_id=0,obs_point_id=0,sampling_port=2),output:2",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.007s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"in_port","v":"3"}],"actions":[{"f":"sample","a":[{"f":"65535","k":"probability"},{"f":"1","k":"collector_set_id"},{"f":"0","k":"obs_domain_id"},{"f":"0","k":"obs_point_id"},{"f":"1","k":"sampling_port"}]},{"f":"output","a":[{"f":"1"}]},{"f":"sample","a":[{"f":"65535","k":"probability"},{"f":"1","k":"collector_set_id"},{"f":"0","k":"obs_domain_id"},{"f":"0","k":"obs_point_id"},{"f":"2","k":"sampling_port"}]},{"f":"output","a":[{"f":"2"}]}]}`,
	},
	{
		"clone action",
		" cookie=0x0, duration=0.006s, table=0, n_packets=0, n_bytes=0, reset_counts ip,in_port=1 actions=clone(set_field:192.168.3.3->ip_src),clone(set_field:192.168.4.4->ip_dst,output:2),clone(set_field:80:81:81:81:81:81->eth_src,set_field:192.168.5.5->ip_dst,output:3),output:4",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.006s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"ip","v":""},{"k":"in_port","v":"1"}],"actions":[{"f":"clone","a":[{"f":"set_field","a":[{"f":"192.168.3.3"},null,{"f":"ip_src"}]}]},{"f":"clone","a":[{"f":"set_field","a":[{"f":"192.168.4.4"},null,{"f":"ip_dst"}]},{"f":"output","a":[{"f":"2"}]}]},{"f":"clone","a":[{"f":"set_field","a":[{"f":"80:81:81:81:81:81"},null,{"f":"eth_src"}]},{"f":"set_field","a":[{"f":"192.168.5.5"},null,{"f":"ip_dst"}]},{"f":"output","a":[{"f":"3"}]}]},{"f":"output","a":[{"f":"4"}]}]}`,
	},
	{
		"ct_state field",
		" cookie=0x0, duration=0.030s, table=1, n_packets=0, n_bytes=0, reset_counts ct_state=-rel+rpl-inv+trk,ip,reg3=0x2 actions=set_field:0x1->reg0,resubmit(,3,ct),resubmit(,4)",
		`{"cookie":0,"table":1,"priority":0,"meta":[{"k":"duration","v":"0.030s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"ct_state","v":"-rel+rpl-inv+trk"},{"k":"ip","v":""},{"k":"reg3","v":"0x2"}],"actions":[{"f":"set_field","a":[{"f":"0x1"},null,{"f":"reg0"}]},{"f":"resubmit","a":[null,{"f":"3"},{"f":"ct"}]},{"f":"resubmit","a":[null,{"f":"4"}]}]}`,
	},
	{
		"write_actions",
		" cookie=0x0, duration=0.009s, table=0, n_packets=0, n_bytes=0, reset_counts in_port=2 actions=group:1,write_actions(group:2,group:3,output:6)",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.009s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"in_port","v":"2"}],"actions":[{"f":"group","a":[{"f":"1"}]},{"f":"write_actions","a":[{"f":"group","a":[{"f":"2"}]},{"f":"group","a":[{"f":"3"}]},{"f":"output","a":[{"f":"6"}]}]}]}`,
	},
	{
		"multipath action",
		" cookie=0xd, duration=0.009s, table=0, n_packets=0, n_bytes=0, reset_counts dl_src=60:66:66:66:00:05 actions=pop_mpls:0x0800,multipath(eth_src,50,modulo_n,1,0,NXM_OF_IP_SRC[0..7]),CONTROLLER:65535",
		`{"cookie":13,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.009s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"reset_counts","v":""}],"filters":[{"k":"dl_src","v":"60:66:66:66:00:05"}],"actions":[{"f":"pop_mpls","a":[{"f":"0x0800"}]},{"f":"multipath","a":[{"f":"eth_src"},{"f":"50"},{"f":"modulo_n"},{"f":"1"},{"f":"0"},{"f":"range","a":[{"f":"NXM_OF_IP_SRC"},{"f":"0"},{"f":"7"}]}]},{"f":"CONTROLLER","a":[{"f":"65535"}]}]}`,
	},
	{
		"enqueue action",
		" cookie=0x0, duration=9.471s, table=0, n_packets=0, n_bytes=0, actions=enqueue:123:456",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"9.471s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"}],"filters":null,"actions":[{"f":"enqueue","a":[{"f":"123"},{"f":"456"}]}]}`,
	},
	{
		"meta reset_counts",
		" cookie=0x0, duration=0.007s, table=0, n_packets=0, n_bytes=0, idle_timeout=10, reset_counts in_port=2,dl_src=00:44:55:66:77:88 actions=drop",
		`{"cookie":0,"table":0,"priority":0,"meta":[{"k":"duration","v":"0.007s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"idle_timeout","v":"10"},{"k":"reset_counts","v":""}],"filters":[{"k":"in_port","v":"2"},{"k":"dl_src","v":"00:44:55:66:77:88"}],"actions":[{"f":"drop"}]}`,
	},
	{
		"meta importance",
		" cookie=0x0, duration=0.089s, table=0, n_packets=0, n_bytes=0, hard_timeout=505, importance=35, priority=10,in_port=2 actions=drop",
		`{"cookie":0,"table":0,"priority":10,"meta":[{"k":"duration","v":"0.089s"},{"k":"n_packets","v":"0"},{"k":"n_bytes","v":"0"},{"k":"hard_timeout","v":"505"},{"k":"importance","v":"35"}],"filters":[{"k":"in_port","v":"2"}],"actions":[{"f":"drop"}]}`,
	},
}

var testGroupParses = []struct {
	name     string
	openflow string
	json     string
}{
	{
		"group example",
		"group_id=1,type=all,bucket=bucket_id:0,actions=set_field:00:00:00:11:11:11->eth_src,set_field:00:00:00:22:22:22->eth_dst,output:2,bucket=bucket_id:1,actions=set_field:00:00:00:11:11:11->eth_src,set_field:00:00:00:22:22:22->eth_dst,output:v3",
		`{"group_id":1,"type":"all","buckets":[{"id":0,"actions":[{"f":"set_field","a":[{"f":"00:00:00:11:11:11"},null,{"f":"eth_src"}]},{"f":"set_field","a":[{"f":"00:00:00:22:22:22"},null,{"f":"eth_dst"}]},{"f":"output","a":[{"f":"2"}]}]},{"id":1,"actions":[{"f":"set_field","a":[{"f":"00:00:00:11:11:11"},null,{"f":"eth_src"}]},{"f":"set_field","a":[{"f":"00:00:00:22:22:22"},null,{"f":"eth_dst"}]},{"f":"output","a":[{"f":"v3"}]}]}]}`,
	},
	{
		"Fast FailOver",
		" group_id=2,type=ff,bucket=bucket_id:0,watch_port:1,actions=output:2,bucket=bucket_id:1,watch_port:1,actions=output:v3",
		`{"group_id":2,"type":"ff","buckets":[{"id":0,"meta":[{"k":"watch_port:1","v":""}],"actions":[{"f":"output","a":[{"f":"2"}]}]},{"id":1,"meta":[{"k":"watch_port:1","v":""}],"actions":[{"f":"output","a":[{"f":"v3"}]}]}]}`,
	},
	{
		"Select",
		" group_id=4,type=select,selection_method=hash,fields(eth_src,eth_dst),bucket=bucket_id:0,actions=output:2,bucket=bucket_id:1,weight:2,actions=output:v3",
		`{"group_id":4,"type":"select","meta":[{"k":"selection_method","v":"hash"},{"k":"fields(eth_src,eth_dst)","v":""}],"buckets":[{"id":0,"actions":[{"f":"output","a":[{"f":"2"}]}]},{"id":1,"meta":[{"k":"weight:2","v":""}],"actions":[{"f":"output","a":[{"f":"v3"}]}]}]}`,
	},
}

func TestScanner(t *testing.T) {
	for _, testCase := range testScans {
		t.Run(testCase.name, func(t *testing.T) {
			stream := NewStream(strings.NewReader(testCase.openflow))
			for i, expectedToken := range testCase.tokens {
				token, _ := stream.scan()
				if token != expectedToken {
					t.Errorf(
						"Found token %s instead of %s at position %d",
						TokenNames[token], TokenNames[expectedToken], i)
				}
				if token == tEOF {
					break
				}
			}
		})
	}
}

func TestParser(t *testing.T) {
	for i, testCase := range testParses {
		name := fmt.Sprintf("TestParser-%d %s", i, testCase.name)
		t.Run(name, func(t *testing.T) {
			js, err := ToJSON(testCase.openflow)
			if err != nil {
				t.Errorf("Failed to generate json")
			} else if js != testCase.json {
				t.Errorf(
					"Not the expected output:\n  - %s\n  - %s",
					js, testCase.json)
			}
		})
	}
}

func TestGroupParser(t *testing.T) {
	for i, testCase := range testGroupParses {
		name := fmt.Sprintf("TestGroupParser-%d %s", i, testCase.name)
		t.Run(name, func(t *testing.T) {
			js, err := ToJSONGroup(testCase.openflow)
			if err != nil {
				t.Errorf("Failed to generate json: %s", err)
			} else if js != testCase.json {
				t.Errorf(
					"Not the expected output:\n  - %s\n  - %s",
					js, testCase.json)
			}
		})
	}
}
