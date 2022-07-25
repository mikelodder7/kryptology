//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

type Context struct {
	state                                         []*native.Field
	absorbed, spongeWidth, spongeRate, fullRounds int
	sBox                                          SBox
	pType                                         Permutation
	spongeIv                                      [][]*native.Field
	roundKeys                                     [][]*native.Field
	mdsMatrix                                     [][]*native.Field
}

var contexts = []*Context{
	// threeW
	{
		spongeWidth: 3,
		spongeRate:  2,
		fullRounds:  63,
		sBox:        Quint,
		pType:       ThreeW,
		roundKeys: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd2425a07cfec91d, 0x6130240fd42af5be, 0x3fb56f00f649325, 0x107d26d6fefb125f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1dcedf2d0ebcb628, 0x2381dfa5face2460, 0x24e92a6d36d75404, 0xce8a325b8f74c91}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5df2ca8d054dc3a, 0x7fb9bf2f82379968, 0x424e2934a76cffb8, 0xb775aeab9b31f6a}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9e6d7a567eaacc30, 0xced5d7ac222f233c, 0x2fe5c196ec8ffd26, 0x2a8f0caeda769601}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdc68662e69f84551, 0x1495455fbfab4087, 0xab2e97a03e2a079d, 0x3e93afa4e82ac2a0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4cc46cd35daca246, 0x54dcc54ee433c73f, 0x893be89025513bde, 0x3b52fbe29b9d1b53}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd96382010ec8b913, 0x9921d471216af4b5, 0xa7df09d5ecf06de, 0xa360d0e19232e76}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x408add78a89dcf34, 0xb15031ad7e3ec92, 0x8ef35f1ab8093a79, 0x23276aa7a64b85a4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdac52436f6c1cdd0, 0x46257295a42ee0b2, 0x3090799e349ade62, 0x261f8de11adb9313}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x51fb0207578466ed, 0xace76bd4ce53012a, 0x45f74735a873a7a6, 0x25be1a7e5c85f326}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdee055cc9572cc61, 0x9373df1526d6e34b, 0x2084c5641a3122a3, 0x3062d3265012feed}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1bd9070c51f40e9b, 0x9ea653d50b3fa6f, 0xa31a6b51060fc899, 0x703ce3434f96fea}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x937e0bd5442efc15, 0xc1b3a953fbd209b7, 0xb3737616f1f7eb8b, 0x5b10777bdf5dacd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x10791e59a7d5788a, 0x12f9041014d93ea, 0xb4bc24f34f470c71, 0x2f00cd1954db2d8c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe912d7ae74abca54, 0xc5c26a35e725fd41, 0xb6af66a891d1c628, 0x3e5ec2bf0970d4a3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8340c5579ef76e75, 0x84685beb75f0fd3d, 0xd3a06c47523190d2, 0x308b8895c2d04040}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x457356859f821f53, 0x8abdeeacf3a1ba9e, 0x43b602e5b2ad8b28, 0xc1879b3610fd2f4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x97b86a707b5809bc, 0x8dd94d73fb34a3ee, 0x5141652598014000, 0x32e8c24d1cee432e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa998c731389a48f3, 0x74fa8b44a0ab13b, 0x1ad03f591da71333, 0x2f03d178701bcb30}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8ff226bd0dd22c53, 0x26157e7a0aa47f2a, 0xe2531d8e88c5531d, 0x13d2bbc731281e5f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x76d7f22ef74ebe99, 0x245727aa206d8c55, 0x4e9bda26e39fe51, 0x72b21a3b6ea088d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x67aff49f723add69, 0xccae0df20e3d633b, 0x85d57c5cda0e022c, 0xa398b1d3e6f2db1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3fda2e26bcb6fc68, 0x593102ff961e4b40, 0xcaca5e29529738de, 0x2af42667a6e9b6cc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9d05ac0056c6910a, 0x51343579482ba8b5, 0x33398f54089da2a3, 0x1879180149c97c34}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfa93dc63c73d6490, 0x898847d037d78917, 0xf104b998c8ba5384, 0x1c6102bfd9c26df2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3b13a7624fe64fc3, 0xae197dfb77fc7968, 0x855c3edfd013edc, 0x247f5769ca4aa6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x58bf743e0004f4eb, 0xa168da971a4635e8, 0xae0d93fc0aa0ca7c, 0x2e94bd91ee0eedec}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x826688455b3034d9, 0xd7a8296917d9820f, 0xbf14001a68903362, 0x3029935cebc0e1b5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x45622b94048f7c58, 0x1025e0f2169c46c1, 0x93dccace2e8635fa, 0x2110fe2a3a9c405b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe6249e1fd6ae6204, 0x359cea9c7fc56811, 0x4561c87d295edc47, 0x3462ff6269ff9b7f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe88503091bf18fdb, 0xc7c9e48c7792429a, 0x7c2bedc34044daad, 0x239b54131c85ebfe}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9f92ac6cdf6d115c, 0x64fe79c6ea405241, 0x3fdbbe356870f930, 0x3c0d419e26ff24c1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeb4e19e81548807b, 0x30d9ca531360e746, 0xe7fd824c32ef0f3d, 0x25c98a72c313174a}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xed7835758762c591, 0xd3a5813b88ed365f, 0x954d02a8633dba6f, 0x3da1af9d7eb3a01e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x86a8692d3ed59690, 0xf2873c2381bf29b6, 0x5d8735bb1f3f459, 0x3c9a66efcbdbfd6e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7acc7d7a0e1d24a3, 0x8614a6c50e15e4f7, 0xac5ee237c5548dd4, 0x12061a68b6963446}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x81bc9093c7730d5, 0xbf3e57fb7d94a12f, 0xab7caef0406ad333, 0x30d704e038c83cee}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x53fd9bef62ab35ab, 0xdd9258a43a400a0e, 0x41fc71c1f14a3fe0, 0xaafb95e685e323a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbb168efcfbc6417d, 0x6eec41829c340ecc, 0x3e1a203ea728cf86, 0x32403a5339001606}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaa842cc888cce8e1, 0xaf60b8e8cfa84e30, 0xa8345e318e18911e, 0x23adb957cfe95986}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9b565aa4fc6cbed, 0x715714218a6da1db, 0x60740ecb2b402402, 0x3446170f139a28ee}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2d56545ce19df759, 0x2e62009452ac4624, 0xf834fd669efdc382, 0x3cdb040c5a2c8135}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2c093b07989ac45b, 0xbc5a7ce41629b4d8, 0xf9f8f9ccd52de847, 0xa6852ff99c0df59}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x62ec3921cae6ad0c, 0xed01dd4b15bc12e2, 0xcf099203d7296486, 0x10c70f52d8e4c35c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe3afb13d98e0aa36, 0xd5c2e410a19ecae7, 0x7ef462f8ef00f1ee, 0x3b2666c865ffaf5f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2a34a9799fb10dea, 0xae3b7ac93a88e642, 0x9ce2e0a5b4676e62, 0x35338d2e290f6835}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x704c2116789cd3e, 0x55c9408a44e87b39, 0x9a178778cf8123ac, 0x2a237d751ce80e22}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe73cc5f3949b8dac, 0x25fcebdc28f57fc2, 0xb8f4c26538ae8063, 0x160d42c37b816d52}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x78bba3a1b4334fec, 0xe1ad733be7312e24, 0x166c29284c5e74cf, 0x1e39c10d204c6e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeba34937ed572fb8, 0xec650563d7045e13, 0xbf694cf0e16bc82c, 0x14394f78ca804fcb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa28d8e959c93e39c, 0xfe2361a2d86799e3, 0xb04a4d8890bfaa19, 0x3bd58529949c0ff6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x29225c95f5b1b6f9, 0xa6deebafdf12f757, 0x4d08632fbf4f058, 0x22ca57e20c30a4e2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbd76f38890b3567b, 0x26cf81518916ab2, 0xe6096fe367359511, 0x1f5e2a08564c51ca}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x522b7903b745f6ae, 0x97976d9feb2f329a, 0x4042a062305c3dd, 0x10e8bfbac34f6ab}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x53a7679692da3aa1, 0xe450599e85d31d58, 0x7b0eb8260f95a840, 0x1ace63dc713e7378}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x725231ba432706f4, 0xccfededdca80880, 0xeba96b0dfbc1ccb5, 0x2584d3df4dd8a065}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe55f4913a1b47696, 0x34767187e1938949, 0xdbe1913ab957b7f2, 0x3c4be85646076541}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x96165fe1910385e3, 0xd8d34657e37bf741, 0x2dc65b5bd92b7412, 0x17c70695eabaad8c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1aa94fbcda906296, 0x92b63261bad15d4, 0xde1fae454d20bc2, 0xff4dd19e7bb91c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9a3c6bb3b3792b29, 0xba9a9d2d8c8f32fb, 0x90cae23b992784b0, 0x682d0d05588a0a4}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8bea2f0e3b07fdae, 0xa2bcf89d80d35726, 0x544cd1414cc270fe, 0x113a9293d2324718}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xae456164d267504c, 0x571cb023dbc1ce73, 0x21bac9730f19acbf, 0x3233efcc4435feb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8c75648ce93bee2e, 0x6a7b2664251ea438, 0xca0e6900ef478974, 0x2ea2eb8e4287afe1}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5acd5490088631ea, 0x796fd55cbfe132ea, 0xca378169084f5b20, 0x3bf94c0b770e6732}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3c7cc5fe22e9da10, 0x8c8312f4ace0a8a5, 0xc87567978ce028f8, 0x5a6f235fb313cd5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2e6558b92407dcaf, 0x47e50ce3601012f4, 0x1e5797dd5bec08f6, 0x3f8733eee4c3467}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x94d2410224bcb62d, 0x3a926c5d9a86b7d4, 0x4e194b53953a44be, 0x352e9b3d78b5bcc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x54883a363d4cf9d5, 0x11f8990c505f0d36, 0x6bc1b45721bf8c66, 0x1741726454535739}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6f9a3ecf74a296b, 0x5de95fe78d089d68, 0xd73cd49e13d43129, 0x2093f7ce8f9a0900}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe9cb00b14e26ff0d, 0x3f08fd94461dc18e, 0x631adca53058abce, 0x3214d344acadc846}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xded7eb4dbd85489a, 0x88fec23b8cd8b77, 0x16d4ed13eab05211, 0x2846ac03154cebb9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfac2a0ad57a4f26, 0xc1f76ecd19989adf, 0xaf30edcd16db54f2, 0x126d20470a443867}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcff7162b34203071, 0xe55b077617c9a757, 0x2130b1adac59d068, 0x14c5aaf1e7b110eb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x699dd6dbcf0482c0, 0xea319e0d0b2bb999, 0xaa9e419d224d713d, 0x1f4d7ca828085388}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe0ce736d12ec2b2e, 0x2f38bcf04ebf093c, 0x4b4b4eb19457afe9, 0x36a6b22a47328281}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x787526c6865dcd1e, 0xc2680fe54617f4a8, 0xb727dbb67712e717, 0x3a271ba53713445c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x806dc7288ade48b8, 0x37ae24211f9b6b9d, 0x8ca3d974dbf15054, 0x10fd6d9432eb0b68}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xec73bef3a5597993, 0x911600cb416be443, 0x3ea4d6875cf79676, 0x1b77d3b73ff96642}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x599dae5eba7bbf12, 0xad64c1aab4e1e894, 0x5d661ccb5ee325bf, 0x126b7751010f9d3f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5ed0e07555bb26cd, 0x6e878aa29bf2c2e8, 0xf5a5eeccbaa31dc1, 0x1d3867eb4e090941}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2937ca036763d28b, 0x86e99a452605b663, 0x724c2748daf8484b, 0xebc687217853e09}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4dbc428bc8ad6e5d, 0xa2f7ba399263b882, 0x7bf0cdf85013257c, 0x28aeab12f70ef4a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3c7790781e18b6e, 0x1bb3023fe1e655cb, 0xed1fdfcb455dca1a, 0x32e02d39a4d657a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x44e6d9c3a1dff228, 0xdf469cea3c0a5407, 0x299c3245b897c072, 0x2be7edf85aee84d5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7cef1e98b43bf15c, 0x5a8dd042cde4ffe2, 0xd86af3fcf5e44a3b, 0x126fff14c130fdf6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x902d3cbb3b8bffd3, 0xd0510141c9be133a, 0x1153608479eba1e3, 0x33b9a4fa153248fb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2267900dcf1e0fe4, 0xaf0c04b7861398c6, 0x55b20fd2619336f9, 0x3729ba618d213b74}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7bccad65b5fd53a3, 0x275fd70abbee0824, 0x6fce1c43407f5ddd, 0x381402c3966b0d15}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd4e90f5f5d1b1215, 0x7abfb980598b6f39, 0x6cc413a7353c523b, 0x3af9e5c6dbcecf69}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfc86b3533d23176f, 0xf2f83c14f801bf0f, 0x5fb324c8b8b84f4c, 0x2a9949609d62d389}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfca79d23caa474da, 0x94af585882c48b4, 0x9184e6e773524de, 0x1971a4bd05472cc6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe14a7a9f4d347481, 0xf68eb0d753ed0146, 0x624211b6c3d94cff, 0x399c54dc6cd81b81}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x86039539dbb961f9, 0xa5af68dc06d8ea6, 0xcc02fcf05e368eed, 0xf64acd9952a945b}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x88c5c3ea3b0286e6, 0x8c0cf8675f0040d5, 0xc0f11c1177699ea2, 0xe3cc78066df561b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x49162b2f404f976c, 0x9a40001b3ac29cdd, 0x17287f8ca8386222, 0x39ca8d14934343bf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa8dd36db44116537, 0x42dbe51eb9216283, 0xfec6c18c5ea56c1c, 0x9b0bc57ea6681fa}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x53684675590d10f8, 0x228bd6ed1447104c, 0xcac8753557c5e945, 0x2533527c9ad29ad6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5e26e312638c73b4, 0x34e1114452f840c, 0xc90124a9e02e5aad, 0x2af2662d93aa4250}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x76bb15558221d4af, 0x41d2a02a322e09b9, 0x29727b4d6c29e353, 0x13f30e86ab0297f6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8b113723e368b29c, 0x2ebddd5dcfd07680, 0x90027a89063fd6b, 0xab82f5420ead368}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6102c2fbeb0b8f83, 0x37caec74787f8363, 0xef4c7fedf4d49d09, 0x157481ef03f526da}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x897dc99e348f8989, 0xfae2d8c6ca328b03, 0xd2a217387ae7e8fa, 0x2309412d902ce2d3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x57895d8995bb037b, 0x4f303912d7010f4, 0x89d126adee61fd7b, 0x16ae40bb98717e4a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x970b8cda0d943140, 0xd07503f516f70525, 0xb14ed69e29e5ede5, 0x2316911f23d9bed1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x632e10c13ba9d605, 0x23723cd16be7a1a3, 0xc0804d9b3264d489, 0x25b18b66bd5a14b1}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2cc13abb89f41136, 0x7b209265228a3e0b, 0xde1b3e0db09f17e0, 0x10e37b1b53ecfceb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x765eb14dd8c343a4, 0x3359bbc963368294, 0xeb4667bd15fd4a6c, 0x2db8142000298d91}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x916a19d68c0ed401, 0x5002ac7be8c90d22, 0x8ae3857c98f24376, 0xb2557905a7150c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf2b38d5f2758254d, 0x236745488b58741a, 0x394898e9d7458c8c, 0x37be2b56562adda1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4aa28e0e6f54d290, 0x115bb413d8c4a639, 0x3944ec613d50506e, 0xbc68674dac60a3e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x82db6a2e85fec32c, 0x97802c924aadd00a, 0xbb6cc8685d8b265f, 0x16b975c2e70b76e6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe2f39f5ef957115b, 0x9a9db22a4623e0fa, 0x86f28972da216598, 0x11dc93268964d29c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd8842bd61b12b92a, 0x6b1e45e4a6b4da39, 0xc2541381b20e4fc2, 0x3cc006d14574ded2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfe0a6647ec349b4a, 0x7d7f9c30364402f9, 0x8f30b3425f1e6b75, 0xa08c94f56352fda}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe8678e25a4d59721, 0x7c2331e36880e306, 0x82ad2f154d53292f, 0x38f905d3bf125a0d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x37c5ba5cf32727dd, 0x4e50703bbe74875c, 0x6e81ccf687c1edf3, 0x13d5a0a5cd167d3e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x549db53e76170f2d, 0x6601954d27f0614d, 0xa2e8516c0a8be8db, 0xe97e0bdc860ec97}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xab07a7c64e7a0c19, 0x3231ef6a85c561a2, 0x45cb8d5c9e495f6c, 0x3c130965bd821488}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4e85b1262b64c882, 0x148a4053173c6bbf, 0x2d30540d2bdf16b4, 0x1c4069538aad6db3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe6f0d54ae64a6b4c, 0x8e435e285f5a0431, 0x89f8a4e55b2e5266, 0xc59b65276e7adbf}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb3c5e9a0a063ba3c, 0xa5f4f9456cd30d09, 0x6d04f16139358814, 0xfe50ec7b61f34d3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x397f9724c5df2d2c, 0xebd5168a65e7dd00, 0x6e2d8f4b4688dfcc, 0x2089bd58ed27155}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4edc28aa719ba453, 0xd106c9909fe6d1bf, 0x583c7c64a6b2b9b9, 0x337410bcfb086e51}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xab6b2a207aa0b5dc, 0x4a8b65d7af08b29c, 0x933af8749e812390, 0x279107e984004c7f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x905ad996b3c96494, 0x64c09614294ad370, 0xe3a6ebea9d5f50c7, 0x39f0c91fd7487f70}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfb555601b96a98f6, 0x2779c5a69548b485, 0x1024d8abadf302ac, 0x9d7b11afa205c31}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x28cc587976dcbd5f, 0x7ec12e67d9fd9bff, 0x8519c024bfaacb31, 0xc3c59eef0b57c4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7049bc5718274ce, 0xc5d45c2b8efbc27b, 0x1f2519b69fd58b2, 0x21d203679cf4943f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdf1c276d845b18b, 0x83b415bcfd6f4794, 0x18cd69a7c02ec588, 0x28286f8440aac608}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xab9395e8f09c0e5e, 0x54e90df06eeabe37, 0x989b955540f5df9, 0x47eea2cb710d36a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1ebb22981a2358d4, 0x978b30395e4ae485, 0x9b80f8337febb2dc, 0x6eadd7dff66e6fc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8235f76b05fb36f3, 0xe81d3e6b55c01c67, 0xef1c4fbfd4f2689f, 0x356208269cd6bf63}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdade3c9e413ae12e, 0xf0e6ec9130474658, 0xaf6a528f73acabe0, 0x25fa114c625e684a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x46eb556fec530561, 0xf037878098d1e6fa, 0x16665ada231de2c6, 0xe5526a3c3f20a1f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8cf9f26ffb620afb, 0x10b561ad3be8bf53, 0xd095012a132c7d3f, 0x29dcadbf2a3da8a2}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc1f246cabd2b3006, 0xa36999931ad6917e, 0xa86d5a37a14ebfc6, 0x233db2873238ccef}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6acabbbf7f09c6ab, 0x62e42b55c506b5ac, 0x20d3e5414eabcf58, 0x3047b6ea2b2ead12}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xebb686baebe27e60, 0x6e299977bf344ce, 0x62074c04b5eaa97, 0x2f8be92e4b475d6c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x68ec476c77321432, 0x6dc59804560e83e6, 0xad6ec6887fa80a57, 0xd2381657826abc9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb377a593d24bcde1, 0x9a3338ee6dc43188, 0xfda6b04c6b645795, 0x1ebafbaa3cac50f4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf53a7e9aa0eaf7a2, 0xc425d1cf708205ee, 0xc4bf63055e40b848, 0x31fd982712a1810}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6aaec40a5ee97dc6, 0x1b740fec535e8d07, 0x72eb71573af7f8dc, 0x32a6cfd27721af}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4422e0763e1715cb, 0x2cc98a9c36481c08, 0x90a04c2c1100cf7, 0x14bdba391dc19c19}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf7ed8041fc74c1ba, 0x2da17664b7e0a39d, 0x7f194ed781738bd0, 0x185a0fb1e41d78e2}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x362d5eb8cf158562, 0x2cbda32193e3b946, 0x54a1587b53b6d3e, 0x3f6a83a8d453698e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe4f331c807d7dbe4, 0x268c8fd3827cafa, 0x8128d4066a80b733, 0x3ac9356638ef0909}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc173b74baf5d10c0, 0xef4884b5f01dcb2a, 0x8ee4fbaf7d1af482, 0x3a631a390c1ace3a}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8db20233cb7664ef, 0xcbd2b0d64c8e2b19, 0xb09d212d4b96af9b, 0xa41894a30594d96}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc87ad145936cc7b5, 0x831d623d07e2d55a, 0xb9f94b89928f0348, 0x32480b57ca35650c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8df84ce2e7f6469f, 0x901e9cc791984cf9, 0xc8fcb9b481d64cbe, 0x3f5d039f9330361e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbf7db6c50e4b6c8e, 0xec86607f277ed803, 0x788b68697fc5fc3d, 0x31e6a675fa09e651}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1132c9835ce2f214, 0xe753150f8c8b375f, 0x8621813806da885e, 0xefb3b636dc3218c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4ce5ce169e972cad, 0x36c4e02c437c353d, 0x91d0f983117961d3, 0x3fab66c8f61b43f4}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x26e7f148037e4831, 0xc898cea85a6d9ce7, 0x296eb709b0bce897, 0x13c7e41ce4a9413a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x364510c0cc6957d1, 0xc25f1640446d6363, 0xa38c8faccf2af7bc, 0x302f893eb7f3a293}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf47cdc9a193b6a1a, 0xbd3e81440b147a51, 0x1b8e11dc417ad50b, 0xbc7ad99db78ba74}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5693220ff22b64e3, 0x95b8a7d6f5f07e88, 0xbb3aaa303d8a574, 0x20f50189f52021f3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xac8d038b73e50e93, 0x613109576b0dfb1e, 0x4ac8d41e35f9b309, 0xa7ad75a9d37c68c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9c979eb72d6864c7, 0x8f1b33a9db15c462, 0xd9dfc2decd86ff41, 0x536ee7d16b7b5d5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x624a1196b5b7005f, 0xb8d9cdf932bdf18, 0x14682525e48adc4a, 0x1d434955ccf03ab0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x719a6381517b8c7a, 0x6168713e68dfa531, 0x9b6cf63daf06a7ee, 0x1d259cdc7f7100c8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6f1e012d7c9270c9, 0xe523c121eae14ae6, 0x50e570fed81bd490, 0x3604d717343ea349}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4eb31e3e9fb8bc15, 0xaa82d889ed027926, 0x861770ba9013af2c, 0x379ab47829cd822c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6f9b1e3a7b6dce3, 0xc5c9ef5c6b7a53d0, 0xc8d12ce69f47f1d6, 0xbc256406e070545}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6440d55f63d23009, 0x74c5732854d7e658, 0x4f7e9fd81fd40c7b, 0x399992d613926dad}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc29845928af2930, 0xa0130ffd9a9f0e2a, 0x48033877dafbdd89, 0x8c39d86214ce71a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9af58f43601d6790, 0xd1af4f75b46b599b, 0x4a8b0b5e6e229017, 0x187b443781223437}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe4304790543ef2b4, 0x9c231e915d799bd, 0x200b86e24d27b2ce, 0x2b71199749ffc729}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf4ba819f140a9647, 0x959dd33caab9515e, 0xfd99be65b9533f42, 0x28a03868f0a95555}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6afe5aee6300eeb3, 0x950ea44539e2fa43, 0xbd9aae96c7978e8f, 0x2e3b4f7256ec9b73}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcc62f85dcccaf357, 0xb56baaa116eae113, 0xd39121b0dcf3259b, 0x46f25e4866044af}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfa220016b44669a2, 0xfbe99bbe5092f557, 0xe04b667a942bafa6, 0x26854edc78b0bd2e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x93c3a940486a4eb8, 0x74cbbc7bd198d4a2, 0xd64f6e74ed8521f2, 0x80843fa28104df1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd544d8f569cb4c5d, 0x9be59548e6b93d2d, 0x65c0c8fe0898dd66, 0x2199702a5841ff1c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf4502dae36e05405, 0xd06e02b361bd5640, 0x783d406554218c20, 0x2f8b5506aeba914c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe3e3f0f92963d863, 0xb3e9c513b7af16e, 0x3248dce06f85e561, 0x257525c4550a214b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x87b7d8d05103a90b, 0x775220d219e02ff3, 0x930897d4af90307d, 0x14fa87e7b059d3eb}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x646e9e36c66167c6, 0x8b8c8990b4cc40f8, 0x2392a8027c056fa3, 0x3468cae95b73113a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbcbaaa65cae2ad7b, 0xa381602916655d36, 0x1e74c496a740a52f, 0x3e5d35946fd70251}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x720ef833761a1b2a, 0xd2e1ad032e9ed61f, 0x1284360fc1bc35f0, 0x1d10c1b1e832840d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf018bd00e4ba7073, 0xc5c912b1fb1f136a, 0x4fa748314dd8ceb2, 0x2a5f7e0ca57c7b77}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcdf3b35babdc87d5, 0x2475d527ee5ef5e9, 0x7bbb70f05dbf6d98, 0x983fe2aff185429}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x88ab0d4fb8c260a1, 0x78a852ca5a6f034a, 0xd04dfc8b6d06ada9, 0x306dbc4ba1531639}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x10dd644c6e5743c2, 0xa2114971e3faae9, 0xd9fbefe6b48e618c, 0x3e38b722e0705ba8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x46ad6b9283d7e0c3, 0x2e308fb2ac0d8c2a, 0x3e1cb59c2a9f60de, 0x3230c38937f63858}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x77fcd1b48730d90a, 0x388ebff7f7ca5f87, 0xa37bd480d5a52d33, 0x1bee5d4ec9503e54}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9e939970e11081bd, 0x72a0c62c6cf51be1, 0x6e8fd8f7900a914b, 0x36036298567aa99c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd6faab04a619d2f5, 0x4a25d62545a6d348, 0xb7ad6f35c22f47b1, 0x1de168bf0fbefdec}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1345bfdadaae5f21, 0x59e61cc1ee11a507, 0xd8115cbdd6eec40b, 0x139c3f6dd5233369}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x58ba96a14e408681, 0xa06d5b071e1ae71c, 0x1a06d51e6e7f692d, 0x1207ba481447ae8d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xac27f34f246f6412, 0x6419a4c21404724a, 0x5eb99bc09179a67c, 0x251da17ba5f44d7f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7c7edb3d3d4d0be, 0xebbd780f9995055f, 0x219149388a5fd89c, 0x46ecaa2536098}},
			},
		},
		mdsMatrix: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x32f4f94379d14f6, 0x666eef381fb1d4b0, 0xd760525c85a9299a, 0x70288de13f861f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ab57684465d1ca, 0xf12514d37806396c, 0x825085389a26a582, 0x308efdddaf47d944}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1b2098a19e203e93, 0x914dcdea2a56e245, 0xc64ed9aa2aef8379, 0xb176f95c389478e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8f85e752c76f7c9c, 0x8297f4f031b02763, 0x30e4ea62df5067b7, 0x2821d0423006dcae}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5cece392cc5d403f, 0x123da1ba8becd2de, 0x193510960c81a54f, 0x1be17f43c42fe5c0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x65fc36e3c120e5dd, 0x51a4797b81835701, 0x3123b2b88ae51832, 0x19f174900d86138a}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd03df46130dd77b4, 0xe694d8c7d8fd4ef4, 0xf71d2a65470713aa, 0x255c475344778d2c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x78597119a27f97bb, 0x1b1fb7c15ccb3746, 0xb86d8ab32d6a6edf, 0xb1e00f75148f670}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x875597b15bf7ed8d, 0x73fa4e676bb9cc5f, 0x96babdc32ae359e, 0x31e6d9f5ccaa763e}},
			},
		},
		spongeIv: [][]*native.Field{
			// Testnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x67097c15f1a46d64, 0xc76fd61db3c20173, 0xbdf9f393b220a17, 0x10c0e352378ab1fd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x57dbbe3a20c2a32, 0x486f1b93a41e04c7, 0xa21341e97da1bdc1, 0x24a095608e4bf2e9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd4559679d839ff92, 0x577371d495f4d71b, 0x3227c7db607b3ded, 0x2ca212648a12291e}},
			},
			// Mainnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc21e7c13c81e894, 0x710189d783717f27, 0x7825ac132f04e050, 0x6fd140c96a52f28}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x25611817aeec99d8, 0x24e1697f7e63d4b4, 0x13dabc79c3b8bba9, 0x232c7b1c778fbd08}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x70bff575f3c9723c, 0x96818a1c2ae2e7ef, 0x2eec149ee0aacb0c, 0xecf6e7248a576ad}},
			},
		},
	},
	// fiveW
	{
		spongeWidth: 5,
		spongeRate:  4,
		fullRounds:  53,
		sBox:        Sept,
		roundKeys: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6342181358ae2f17, 0x5a321a1614499301, 0x4359bc382232456a, 0x3c06cd69a97c028b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc8f709e31405ba8d, 0x2ad4d6aa3c7651a4, 0x64ceac42dd7ccf06, 0x35c6bf27e315e7b9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x42218b11632afaf, 0x90b0a10532f0546, 0x9e04edfc8863e7f9, 0x1ff6086dc7ed5384}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x16d30e86f07fe92b, 0x49034fc6f7a0437c, 0x7e969951637e0a28, 0x290172d88a15ab18}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd254d8abb8cde612, 0xd4661c22ac9199eb, 0x512959a2410883d0, 0x35b38913f7bb3552}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x49f9638de015c972, 0xad7264c15c3300ef, 0xa62f4865d8c45b04, 0x315e43c0ae02c353}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb3801cb83df2182f, 0xcaaccf3669280a81, 0xd23d1db585bf366e, 0x116befc5fb4b732a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x208bcd0d2edd006c, 0x10eb450d1445d24e, 0x430c3ea6421ac01c, 0x2faf9819445679d3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7d2dedb966b0ebb4, 0x4209eee542441a34, 0xf0d333d24b06af71, 0x10dedf831bfe44d8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x382b013bde3a59ae, 0xebafdd87c283d4af, 0x32d9c8ef1bce04a8, 0x37556fb5c9dfe161}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe7016d6ae4ed55a4, 0xbadf50c278ef084f, 0x5f2fc45b67f08884, 0x718c8e8163346fb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2d21d77bdfad5760, 0x6ed140b4216a3a63, 0x43b402fb536c00d2, 0xb47d43fb0ea216d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x36a2aed80574b2f1, 0x43955b0622809eb3, 0x6feacba71072e845, 0x28df76e003ac1ce6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x95e3a1a7336bd728, 0xd87d937c7f109e25, 0x8ce854afc1645048, 0x2fd788ebb6f37b5e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4e4171605858df04, 0x6f56c8c5f323deed, 0x6a570e86d39294ba, 0x6a33164c054814e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe182b857a075e511, 0x1246b8af401e6e, 0x498681baac02e546, 0x317e99888d6935e3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbbb9ff9616a4c70, 0xbd5c5a42104dcf4, 0x92895e7865a8d476, 0x3c40b0adcfe6deb8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfc63b58d228c1ad9, 0xb912e4ec588e1a52, 0x601be7d93b9e73fe, 0x1d52635b6bf4a796}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8defc77d5096467a, 0xfb8b83bb3cee16b9, 0x1498e0216590fc1d, 0x337571eb0ad8f47a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8fed932080f3d458, 0x8a1ca06c98c3849f, 0x1644f9415395314f, 0x2919282dc8950b51}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x749d4e7efe5fad9b, 0x33b58b4510a5f0a1, 0xce62030d41fdca38, 0x239d5d59f87e0ddf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x55d59bdcc39fb71b, 0x7c183b304cad27d1, 0xb84182c63c47f121, 0x2469351d6d7b0ac4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbe942f1ad599f550, 0xfa1e12f8c552df88, 0x1ce36aa79f22cf45, 0x18e7e49a56a18f41}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5a85fc171d1c0130, 0xee3b8aebc4fb144c, 0xb7910bda1c5a2946, 0x2ef6a9412227b683}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe3f397f0634ba64, 0xb24c5da645b804a8, 0x8efdcb393a1c51d1, 0x388a37934aa31a42}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf0aeba711a86d351, 0x917e0a9875d8182e, 0x255ebbbe4e9633da, 0x3edb9c2a8feb51c7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf7085a35274435d5, 0x4e859571631715f8, 0xd465913c64aecaac, 0x3df65e7104e3d373}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x95964ef5b04dba5a, 0x86296dcb59e4f8b5, 0x340fae9fdeb8e75e, 0x3c095e04bcd91636}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6ca87eaf42d54b9d, 0x5efd6b2fd3843e9a, 0x1a9120a05cc3b07c, 0xbb0503c4b83daca}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfdd237f0786fa203, 0x76e67649a894dff6, 0xcea3a7485eb3522, 0x371ed39b30e34b8}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb9ea58fb107cee4e, 0xea9f1a7f2d6d936f, 0x60883d0bd19662e8, 0x137e698d12aceebf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x37d5024d477cbc47, 0xbd489bbac329f617, 0x37201ef9b7544c1f, 0x1019235cf42868cb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa676a36a225fd2d0, 0x16c1d622bd02030a, 0x71b81aab0eacb647, 0x36af1193dcd5753f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe00395d80fc7fa84, 0x2122fd483a170d2e, 0x6786ca04c13fbe30, 0x159d681f1d489146}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xacbab2cc73b4508f, 0x47443d2762112d66, 0x26c9a77344312882, 0xa68b32d6c0b1024}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe5943e9ec5816b5f, 0x78f97275cb9e7f63, 0x28d993db0402e6f5, 0x35023474a298a50a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd5f6f7304d58bd86, 0xbeed688b64192acc, 0xd7211bea14f1a406, 0x24f92d631c9c4bc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6952a1fd17d693e3, 0xc04dd964f234b8cf, 0x7caf0fe8884ef070, 0x1c1fdcd698bf94b5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xca8b6804ac41ba2d, 0x81794823bc0576ff, 0xd4a19f41722a0f09, 0x2846565f83dc9972}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x51ea8b6d4a20f06e, 0xcfc9a709b77cbe9d, 0x30ff8818851924e9, 0x211d3ce41b7ee763}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xff21fe3230917894, 0xab2870fddeb86f88, 0x62e4a41add2270a6, 0x15884194ae363d14}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4a6fb13b70e67a19, 0xc5247d0dba887080, 0x31b4c6c5e685c605, 0x2e9f9208fcc2515a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1c90f4fb1e0414b4, 0x8ff65aee4323cf80, 0xa13dda064773ad4d, 0x810a513ddf12c38}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe053ad98a6ec9bef, 0x39b9faf0e080b472, 0x818c7ad0f950eae0, 0xf1cd4227514673}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd196b25dc683b945, 0xd724c2ad624ad4a9, 0xa02ff7daa5b740a1, 0x15d55dbe3c7b4e13}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb315a1ea41fe829c, 0x18713cd306622126, 0x6118592ab4ec0503, 0x3ed3f347d4db5134}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5975228afeaccf0c, 0xfe4e4239b60b0efc, 0xc9cca90df89e496b, 0x230f526cd9442560}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5a49f311ef676e8a, 0xad7cb07e3ed9efad, 0x2a417082abc3cf1a, 0x21601ac12eba703e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdf338b83df06f68c, 0x63cd7cb53f8cdce4, 0x1f0fdaf0eecf7ab6, 0xcb74130d7ea6889}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd99c453addc57eae, 0x2e5ca7b4ccd548e9, 0x1d61848bbc4141ef, 0x1502dc917545edad}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x31688174ae3a3088, 0xc2f2735e215a8858, 0xe021199a3e4ad81c, 0x3c3a13210a719854}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5cd766b0b1aa7928, 0x9469f3c1ab1f06d1, 0x23c181781a8a1af8, 0x669f23736966be7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5e43af558f0a0b, 0x7568a76e8644aa47, 0xa49bfc0b2c3a0969, 0xdaabd0e2866cfd8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3f57582785bde7cc, 0x95a273aed529176e, 0xef25328aff37a9e8, 0x116b8853ab55ee5a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeda91d71ffd7b2a0, 0x6efe645946126c4c, 0xe9f09dd2a7027804, 0x387a2c92b4e648d5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x64ab4aa2e9f0aff2, 0xe966eeaf6883d60c, 0xb94697e6a3a0a4df, 0x38f0fc799ed7a14a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1511dd33c4afdbf3, 0xe36ee2b5ffe811cc, 0x505a5de39ec98985, 0x3df8294a06678e64}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc710119f6242f55d, 0x2466c6cb6d325477, 0xb1774657e651de5, 0x310d190e78ee5dfd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb1e6071ea081861b, 0xe92b3ce474295159, 0x77456109d94dc351, 0x1d893fd638fd7a1b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc782a16511338c59, 0xd18c9bc3c41203d7, 0x847badef6c2b829f, 0x126c269e06a4a430}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa0e7271d058e1b65, 0xc29f191eed5dc914, 0x89207dbde1650706, 0x1bd2a2d62a9947b2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6ae20ca1c2d65d68, 0x80f9d7daed9c8c8c, 0xad5cf3b156b2f1de, 0x509f8b72998a87c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb03a6b97357d97f0, 0x593eee3fbeacfe95, 0x9fee173d856a5b7c, 0x133fc88ee7b23b27}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4b9a0736e24a0f26, 0x405d5a665f66fbc4, 0x4d4d5268d0b8b9d9, 0x3238606d9b26856a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd073bfc69cab34f0, 0xb4133b646eb1841b, 0x10a149c352b6f7df, 0x20cf915f29d33c57}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x307d2b8cb0fd415, 0xc8319598907073a4, 0x6b773db66a05a6a2, 0x33e6c0d1d806c5ce}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc08315afa7ec4292, 0xdf1042b5d5054c91, 0xa610476590769545, 0x354676a843acb066}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa1c7c9de915601be, 0x69cadc4f1bbf31a7, 0x47661b8d743f21e, 0x2939e4566b8e1260}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf8166d26b5875ae8, 0x391c8625906a68c9, 0x97a671ae3e7920b6, 0xb62d4ddc6a61f73}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5b13bd8369bec282, 0xe2ea0c100e5347a6, 0x2d9c57262923cb1, 0x1e31165d6dc07d45}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3df3f3bfd54018f2, 0xca762a746d00043e, 0x25022728a3503107, 0xd5efa7f874457bc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x613e721107b4b48d, 0xf10823eec3d12df3, 0xeb54dfa62698b875, 0x243340259e551904}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1ce630ba8530b2a4, 0x6f5eddfa4f7ddda2, 0xdffb5a531052c7b4, 0x3c6b192f75dff4c1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8d8f971036624659, 0xebd0ccfe39e0803e, 0xebdcb61a65d66931, 0x21868796aae7a40b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x22e12b186fa512c7, 0x4968f02a800e1ecc, 0x4725f2ec01f4b71e, 0x28e74c6a4f22fcb9}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeffca0f81d56aa11, 0xcb0ae88503b5be82, 0x69b43848fe8e74c1, 0xf0b271c54f3b2a3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x23db18e63a2414b1, 0x7eba0c1ea4e2d784, 0x72108a3064e1a124, 0x138c36a9897505ac}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb93afa2c44d2b18f, 0x616aef5e3ec452fe, 0xcb15eebb579916f7, 0xed9d9c3d23aaa60}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x19c722ddc6d11a6c, 0x933aa7e601881608, 0x3d680c98391faed1, 0x2809e56840f1eca3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x682adeb5d9a53026, 0xcdb02ab94f3e9259, 0xed7adc874c00a2d4, 0x1764188e52d76c52}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2cb2173bfd2a8b7d, 0x742418360f62a8f4, 0xffa5daf7a2f06510, 0x2622bec30f05eda4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x956300c0a931ef90, 0x3e8dcd122d9b3016, 0xd77959f2fba021a4, 0x51f68f4d9b5836a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcca7550f4e2663fb, 0x3a7115aac8cd273a, 0xfa9108f48b6ec0f7, 0x2eb9ac59d63b2756}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x25c658fd552f8699, 0x24c4b27a4de55c10, 0xf2a39825d38a8469, 0x261dc2c828f9be1c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf33c05063dced35a, 0xb0dada5d213d36ea, 0xe1a0c81f1f6ca22f, 0x3b5ea3d73588bcf5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5938e55ad487efbc, 0x65ff0bdaa2002589, 0x24f12d149cfb0ad8, 0x2d7f7be151666e78}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x832fab7224860b2d, 0xc9f4cdbadd955fa2, 0x4aedceb5506c2655, 0x1c44fa130dd1ecc7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7d034b1f6a58ddaf, 0xf897b22ef62bf04f, 0xd973ac696faf14aa, 0x31548d27d817dbcc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf89844128d9c6ae6, 0xfc4cfe0229c7aab1, 0xac2b0c7d97647680, 0x1e1d5254aa0782f9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe8c1dd74ba3631f0, 0xd81c8d077b5a6f56, 0xf3294e721e883318, 0x380d3a1eab70459b}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaba511448d72ecf, 0xbf82f1fdf1687a8e, 0x6313bb88e45ffa56, 0x2ae425e1e1234cff}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf4a6807d301a531f, 0x96429863d70e0604, 0x15bdd9eae828ddc7, 0x31f0f80173fe31d7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3a6d20e8dea8c483, 0x2adca6c88e7509ef, 0x48b1d6d05be6c961, 0x35053945aa6e5402}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdc5f96bd86658107, 0x5aee32dc2a32affb, 0xe200cec62dc0d495, 0x1055b57944bf554b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe1ca0c53b24b06d, 0x528de276ea0c8c5e, 0x1c7ffa0b483f3002, 0x1c72f58595847427}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x26a28a08b5b246ea, 0xba3b8d9f4f4b0f41, 0x99c9ed2c1fcf4a3e, 0x58070c1e7b659c5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7aa8e9a2d203b7f4, 0x9acb8ddb590fc9a0, 0xd7cf3e5554e162c, 0x17769ee1912d75e1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6c6901252870a99d, 0x9a4108b035e55928, 0x297dab35f2c77cae, 0x31f2978ace0f7e2d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfcf1119abff1e989, 0xe8502332327be648, 0xa8918572496177c5, 0x1710468c2227c8d6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdd2bf9131735dd76, 0xe43ec3b817349505, 0x61ec884ee479524b, 0x377c72d607beacc5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa9bef84e0b68b0e8, 0x2c4c8f2ab7b0c9fc, 0xee234cad52493f69, 0x1c5bd50dc4a1fced}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x57f989e88a97334c, 0xf99d4d667c1b859a, 0x64164c1e8e48da1b, 0x36b841653e8612c5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb55c8effbf87f8d8, 0xe15c71abf8372eb, 0xc606d853488806ff, 0x2c6be0beffd5a9b3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x97235a2b7f573c80, 0x8f5053ff091130d7, 0x201611ece80cd2e6, 0x22498e90ad20fd7b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb25923ea87f4f825, 0x1faf60a8b1d87720, 0x1c480f9378722c18, 0x187ba4d5f603542d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2553e37a713a8650, 0x4af5a87c8bb53cde, 0x9470f8df7dc4e62a, 0x1147db739156a158}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7a58fe90b257b6b7, 0x8ee9df6553d968a9, 0x85057b2342c19359, 0x3ca66ad9e8533b29}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xebe091f37f855e8b, 0x78312923a64e1e08, 0xf968ab79c1cb96b, 0x84c6a2f87e5877d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd3393bcf45ec7f72, 0xeebaad3d085cc500, 0x8dfb7b13fe964753, 0x29e0048c6a967c5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6ee6f52f14c5c52b, 0x51eda970b620a200, 0xe1239122e1ee6ed3, 0x20241311a411c6dd}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3a632070a61738d0, 0x58360c4de1248c90, 0x2007e0611a3ddc78, 0x318e43c7104b5d29}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe11a8859f0b07f43, 0x22423a78bf5d6ce7, 0xfe8417dfe2f81f05, 0x2a9cf2284ea93e6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3c682a7371dae56a, 0xb537b6fc7564fea3, 0x4c8c6573f55fa435, 0x152489488b5a1639}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3cf49703bdb0de0, 0xf828bf910f380e10, 0x8fb14d900fd140d1, 0x3f6cf44c3e3ff6db}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7b70aeec460c3296, 0x2afdb7b9dd091761, 0xe5b3b021d8f70e09, 0x1f75fbbd77a4b405}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb824cf8de5beaed8, 0x70a7fe173b87433b, 0x1a8efeec667f72e4, 0x39565d2fad0c609a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5cd0203a1d4f951, 0xdb78389b84917080, 0x6c4c97504ab70cd5, 0x29cc98e95cf64495}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6bc75c72ecd52b50, 0x33afc1a9068b1413, 0x33daf830e0a55f27, 0x71875230561158e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb19ed2b87a280098, 0x1e9ed62c5d6a622e, 0xf1c47cd609238e2b, 0x88c1888884476d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x69ea31042e6e347f, 0x9bb2a44f8642afdb, 0xeccc2d81df513162, 0x3af58f661fb1f19c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x46713a78770b8c85, 0xb3ccf0a4b425690e, 0xc65beb7710375cf8, 0x1c83ac2e75d29e4e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8df4d89a09fbc390, 0x4d57e4b593fc2239, 0x94b4e16defc746d7, 0x1e00fdaba6801cc9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x62d3e199fefcf465, 0xddfca365e5282190, 0xadd48dd560275162, 0x250a1b6745f9c2a6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x935e7ff4c5ad3690, 0x931629e4dcf656, 0xad870e5416ca92d0, 0x2d2002e4c1a7fb42}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3020c37bbe98a69f, 0x3bbbef2df0bb0743, 0x735468317fea682d, 0x3bb75622e8ae0e5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6d101c64f48442cb, 0x9c4d0d7cabbe37d0, 0x6e457716d0cc5c54, 0x131685a66db0333d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x48bcf6f7121dc6fa, 0x44ea62ad25ddb6aa, 0x8636e258625c8e02, 0x171b08836f73a4a4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7b5d53163078c6db, 0x79f022d48797b027, 0x8a6611711def9ec3, 0x281eb0327e36241a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe807c130c139b23f, 0x8bd55fb76af83b50, 0x2917722317575e1b, 0x8f90e5cd2c3173a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4759babec3357d26, 0x265b8a66badcbb36, 0x44df217c22db1fd1, 0x23c7ef2b68b42cf3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb6a7c51b7ecb6bc, 0x4d1ae5944bfbeed8, 0x864b9db1caabff7e, 0x39f90ff79f187276}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd1969a2901b910c2, 0x67af6508acaf97a2, 0x8380c23a59ae6c60, 0x271d877b5644c4a3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe17e8fd5a391261a, 0xab17b0e6a4632c50, 0x1c3e97e07f259c9c, 0x2d07bd641a6586e2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x138aae9b3cd42fb3, 0x81f64f590fb78cb4, 0x885724f615f7f233, 0xa63fee53381d1b6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ec005773e160199, 0x475ef3383e134dd2, 0xce774f49e51de44a, 0x36ef885cefb664f8}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x37420d26e384e4a8, 0x1742df50ce970b26, 0x99f3ea60e2297d13, 0x291cc0cacac121bb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x59992f7b95d59d06, 0xbfbbbce9ffae7ef8, 0x230d4b9bb86868f8, 0x135612cee5c3cbf5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6ab6b33ab48fd8b4, 0x2c46df90b0bdae8c, 0x31e33e7cf970f45a, 0x36c4a50b91a1475a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaad1c48efff98a5d, 0x7a478e439cc52346, 0xb77125717607cc5d, 0x24c45ff83f2e80a8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5103153d6fdd5dfd, 0x45b61844136521c6, 0x41c397561d8772fd, 0x1ed1ee06b89dbf2e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6c5059eebd2c5991, 0x3d6cf236df839e48, 0xd92711e12b52886b, 0x29829fb71567bb3a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x771a7702e2a54d3a, 0x29b8e99e7644939b, 0x3d453254475ea815, 0x2e5f8163d03b6cb5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x263df2c33bcdbc46, 0xfed7cba7787b1a36, 0xc315fa3c16682da4, 0x2ab983af9d9b6f25}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8a0353e693c8e2c, 0xbe92370d0d219261, 0x723aa4237242dd57, 0x25361783d1e56fc3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7e7de67d78a9ff19, 0x83c2d2fd23156a32, 0xe65e5d243aa459b6, 0x35813f92ed31f777}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4819c016f5a5c698, 0x4f72e64273a5868e, 0x61751f954f65b95d, 0x379db14ab6232b32}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5d8d95a7f9270b96, 0x61541332ec3b7a2b, 0xbf5b05056d41baab, 0xcaf69513fccef00}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x966ebe56652901fd, 0x3d01e1815a5244ad, 0xd62a7487593ee708, 0x5f1ef41b294e025}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xda81a0814d58ed14, 0xe5824bb0a3739516, 0xe559c39f79e50e7f, 0x3cf706e11c52afd4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb07502481fd9ac00, 0xbe85d565f578f9e9, 0x25e2168d537c5428, 0x1f8caff53a89afab}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x67ef0684d24ef4d6, 0xe479b8723faeeb8a, 0xed152c7174bce1c6, 0x2c3879d3206619b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc0d0b18f192aac4d, 0x8ff92db980036473, 0x39a88f384fb77d28, 0x9fe5e9d746e308b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf10d5629175358d0, 0xa258ea27ec17d224, 0x3730ea6667ba6289, 0x1f8bfc64890f7e59}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5f8c12d96d37065d, 0x4d7ee138862aa83, 0x4a18488a63ce6118, 0x1930781a4f270e4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbd4453cefd9ebc0c, 0x14827cfda7ed7ee8, 0x3dd6c45400957559, 0x33c9719ccdaab5b6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xed0c855c5de359df, 0x6871e8f1798b7bf5, 0x3803b19eb2c1f511, 0x1b88826bc36516df}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xecec6a0bd180a9c0, 0x954e9adfdd68e064, 0x323c890828d78811, 0x2c89829ba7ac7fe7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x623862b5c28aed0f, 0x544fea8657153f5f, 0x41139508c925a0b2, 0x10d5e06354bae812}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeae3b52c47a3ad31, 0xa40c52de4949ba9d, 0x239515052b2d0bb6, 0xc68f2ca20bfa5a4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x86da286806879c23, 0x2bc62129dce2d327, 0x8f8f1b3f3a607809, 0x257de258bba457f3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe55015708a8bf114, 0x8f7b7799abb7e89f, 0xcb8fa2a6bf9b602d, 0x1dd3b45e4f2bd1e9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa48bd0f7b831b6af, 0xbe6ed2ae7e9b5ea6, 0xecdd091614986315, 0x1bcc64e2d4434539}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xee95991ac731a5d7, 0xb643176046b51d45, 0xf396998dc25f72a3, 0x1474b46564931dc3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe8973ad2df550e5e, 0x8561e0de83378bad, 0x90495ddc20bf8d64, 0x2c8ee5b7e87d23ea}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf15e8598d3360040, 0xd9237d9f5bd4da94, 0x2f32ec74a0b7cb8f, 0x2bfa790791857d69}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x51ed3818b8a671e0, 0x93f8de29901b0101, 0xdd6948f429d84a64, 0x339864f118ba5599}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8070718964c6881, 0x664a56735cd1d096, 0x966ebb68ce0c59be, 0xdb44ab4420ed185}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x390fdea200fe8c8d, 0xb9ddf1781fc7dcfc, 0x6ccc8d97ea91a52b, 0xaf86429842ad1ea}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6fbc15b9f8ee61d5, 0x485407282205ba19, 0x9f2b3a9eb0762424, 0x1167e61f6e4bd42e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9b2e606d2a12a53f, 0xfe4ee2337eadcc76, 0x97152598ff76e36b, 0x275e80f05a7648b6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc3cc461cc12d86e3, 0x48b15302057c1d0e, 0xef7a34bbb6748beb, 0x286c7795696d139}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x337d4ce46c81b278, 0x2e5feb77948c70d3, 0xd82b4f43ac0ebab0, 0x23a5e817dfdebe91}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ce1459a01867e26, 0x224b53d8806aa3a5, 0x1bba8ab295cb47f5, 0x6cbbeb19cc3e900}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1774396945cf1d1b, 0x325ec3d335425b6b, 0xdaf58659cd291e5, 0x3f8cfcb73cb1aff7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x31812080ad76a765, 0x76b57d46db21d506, 0xa9f0b894c076a2b, 0x6328153e24ddb21}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x635e53a6c9b16d33, 0x39a4746bf0a3364b, 0x61555f31318c6ae0, 0x3b775cd07e4fa0ba}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2cc47754e893144e, 0x76f56441be34ac0c, 0x580502c5981f6c05, 0x3f1912d87eb51724}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4ead108af1a4e97c, 0x14ed7a0fc16f0e1a, 0x88a0cf37b2ee10aa, 0x13aa67b47ce7c7fd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf54922d903cdce93, 0x825eb6a0321c91fa, 0x6d71f23e5b2a77ae, 0x31d82d03cd7ef1f8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf6c8ba6acea0c3a8, 0x3dcdacfe5ace7aa0, 0xbbbff1c714c8bbcb, 0x26b4c61ca5f05c8e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc2bddbeee6db7663, 0x5de993fdf4bee2bc, 0xc5598a002460bb6a, 0x195ed57ac7350182}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa3c22c35da970f5e, 0xca1c98fb8ebbea38, 0x1fac0f5c50dfc365, 0x1aef8ca61af69bd9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x26e8837fb91809f1, 0xf9688f1eec8f7e7e, 0x610d6fea8d7fdb89, 0x3d0a1bd4d427b4ac}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4805ec51b5a8b95, 0x35841575c48b553f, 0xefc86563cec776dc, 0x2840e92680329f35}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x88aadc874b15e054, 0xf4c407659f438e86, 0xc78f11dc3ac39010, 0xe83c809dce62ea5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa0d5b4ce25ad95e3, 0x4eb48fba265577ca, 0xec34d547e740b067, 0xf87455a1a87a825}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7171a3dbff618247, 0x8f77af4f143160e8, 0x639543558218623e, 0x1ad8547be9074db4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa0dbdf918c38f312, 0x62d083dc471500fb, 0x5358448cc9aad1d1, 0x5825571f70873cd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb9c01a42ad74f7f3, 0x96425e46aa40f166, 0xbc305b6f8c2ca3c1, 0x38885a0e462a0d16}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1f3b4561c10caa2, 0xe7f7e2edd641ea35, 0xd946c46002ec9b24, 0x22dc4744611dfaf}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x89d2596131b9d801, 0x6d61479c7e6f6d9, 0xf5aad5649f5a1c79, 0x225393c033553d15}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5b0fdd7cbea91565, 0x95e46f19a0dffebc, 0x91d50f19a3a46071, 0x2c03ec2d9ea3aaaf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdecba3c94506fd1b, 0xa07f4c4397072961, 0xc072d04541ab3761, 0x250beb5d4be1732e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9ce4550f36a82208, 0xad906f79c2991285, 0x82adb87da0fe9206, 0x34aff80145dc173b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb84407732055b44d, 0xf9c85a0309677606, 0x1816b1a6361d2c99, 0x302b805797745fa1}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbbfbaa3655132a2f, 0x85de63edc71b8169, 0x231b387734b227a0, 0x791e6d7e390ab58}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x846a348eee728261, 0x91e35881244dcaed, 0x8755e3179f39f84, 0x11c757c8adbbcee2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdc5b85ce4ff2e16, 0xe6680a9d77d56b79, 0x2e1d8a190b81a71b, 0x110440e7f341ccbf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc5714f4e64e4f5b5, 0x9073123174ba32aa, 0xd1aafcb808fb13a9, 0x2b0bf27c449467b4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x674d2c9c2a9f6c33, 0xd64a81fc8872e544, 0x54da3af1c7ea91f3, 0x22bb7d2c8479681d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5ea26e9a08f957a5, 0x531b4a8427d261c2, 0x92a9d9e3c38cfcf0, 0x2006044428827241}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf0834849c1fecda7, 0xfab565ee5f9319d, 0x3a3b976275b87643, 0x2bc18d1039d22ce7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7ad9bd18d3ef9d11, 0x136c2bdc157de581, 0xf1999edaa1f99ec6, 0x3bdb875af3652fea}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb06ff1fa4faa6be7, 0x7b65a2d09d62e6fe, 0xd52851aa16d4a33d, 0x3b7e6a651e5f1100}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x70b297d3bd617bde, 0x42dfd73b30a28150, 0xbcbc0b930ad9480c, 0x14452569cf1b7495}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb997f89dc4f23510, 0x86aeec894d2eb890, 0x40b5eb4203777c22, 0x3f6900dd45610c9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbed1fbbc558ae3b9, 0x7b9919fc76fb8f31, 0xa8155c8d8f223d05, 0x7be199f23efc89b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x124bd2f29dfdfc99, 0xa3cd06dc334c28dc, 0x8321717bb314584c, 0x7a90593068a94cf}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6d262cbbd1c3c7a3, 0xfa55dbcbb37ab4e4, 0xdfb0541244749109, 0x1b42310efbbc8ae1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x159b02d7b19c8807, 0xa3155c41a3100f0b, 0x649691f59c73a27d, 0xb1c6cf5eaa1a3da}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x56a321c5d5620a4e, 0xd704e017be94ce48, 0xbb7e58300ff6e106, 0x231353460278eda6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7f24d9a9e896902, 0x379dfae44f3dd605, 0xa756baa38400f59f, 0x1ca15e781769cff3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3b1d025a762cebf4, 0x9be99c300caf395, 0x1ec3a4ee83fc2b9c, 0x1db9c130790aa77c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x92f350103a625f89, 0x7f7abde4baa7fe7c, 0xdb4ce7149975b21a, 0x37619aef93207815}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2df14ae96e32f360, 0x8154a50068c1d6d7, 0x3696523ff84dccbd, 0x3d71103fe9b7d2cc}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdc8f123847c2f6f0, 0x772b9f5f133bb07a, 0xf48472df2de5637d, 0xb30587972382d91}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd32076031e6caf, 0x7a70c0a191315b1, 0xc72d68ebbd493f22, 0x26a6b863263ca385}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd1ad7a8f3f52bc58, 0x7fd97d9102a5e717, 0xdc4dea9fba06a94f, 0x24292fae82eb3182}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9c8f6b9aed0c14a, 0x7ce6499a8da0ffc5, 0x4c575abbd55a091, 0x2ffffd706225c6b5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x51ff57474553fd13, 0xbcd2c2f63e851309, 0xad42d629fbc07620, 0x37cb8a314456dcb3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9e725f4a1ea322f0, 0x51275d226f5fc65d, 0xcc96b5ceb521cae0, 0x31697ac9e08fd09a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfbbfc3ed25936e24, 0x885d8e71956e9fbf, 0xb8e0d819be1b2b0c, 0x2a27ec07450706e5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb86f23d85d56ff2, 0x25630952048f156b, 0x96949d2297030e85, 0x28ed6be9457a4c1d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x85cefc2d5a4254e4, 0x93335e124a410406, 0xe2caa252d7d83ee, 0x206bb8d1b294acc2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaf3c9df6a0ed5396, 0xce5b0093a6e41bfb, 0xdae7d2b6669cdd65, 0x91670d7e0c906e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x848e19c09bf3ab82, 0xd37733a864fbf5b1, 0x5834568186cadc57, 0x3d8894b3840c836b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcb24e184ea8d715, 0xdde18b32791992e1, 0xc754f597613dec6e, 0x124ddceb631af8ac}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x200fede77fe9ccaa, 0x4120a35be4499eb2, 0x6bcb74340da3069e, 0x18d40006660a4d9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8ccd91c1dc2b219e, 0x1dc15dbbeee5b7cc, 0x30e961143289ebc0, 0x33aebd15476f6d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd4c03228e1165ff1, 0xe755127566374ca5, 0x5eb5e5f7835f51b9, 0x11d1f3f590664116}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1c2a43421f2b006a, 0x6258ea61fff6649b, 0x5a847a0bdf1ff16b, 0x2038498881736f80}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe603ee6ce8b0bbc6, 0x620a0a604d315efa, 0x40378c0521e6518d, 0x2d4d8c63bccec23}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa77ca49f7f8b90ff, 0xcb7652bf1a0cf5ea, 0x3d911a1c6e5c74c3, 0x1a8c15f40c9e99d6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x293a2d7589738448, 0xea4c1d5f407e77d5, 0xee7f4d7f7d8d69f0, 0x6d9a037bd4006b5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7e0382dbce83b459, 0x8210fa8a33a15c2c, 0x4da8c81848a7e20f, 0x35c902f371d587a5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3d331566c2c6c483, 0xc66d7c43cf6c6899, 0x7c1c36147e850129, 0x18396a316e009c03}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x16d27bc62b29f952, 0x65a7c24e59dc8b05, 0x5c0acd2a0f886241, 0x15e74885451d7b84}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe3a5b84fbaedfd4b, 0xfd3304cb4b735b85, 0x8d8df8b6031ccd91, 0x603d2627ed921bc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x194cd2aa6240d213, 0xa3d4d947c6027d50, 0x7355e133684d2417, 0x3a4ad2ca80689906}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x754062c7dfe10fb, 0x15be7881422ab514, 0xbd3cb5e4447b5b04, 0x267919778e6db957}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9e687a0099aafbe4, 0x8716f500deb883a4, 0xc7c44b3a4227e0f9, 0x36dfbee5ac583fec}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb9c5848f3b063542, 0xbd7beb77de16d02e, 0x6ed1369422f1597f, 0x35cd85390d4f063e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x50a256d280092fdc, 0xd2c2b4dbbb258e39, 0x9c6679aa1c4480db, 0x383efabe992c0d62}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb8fadb8a950482a8, 0x6279eecfb927c631, 0xf8b75e3cffc23fbd, 0x239433b63ac65264}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaf95feec451ffd03, 0x7ad4f5520a280f0a, 0xfb6d86aa8efee6c6, 0x5ad99e8a107bd86}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd47e6d75a1e72978, 0xec21efdeed48fc4c, 0x3f95628431615152, 0x321e3149a1bd5bda}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x366a1936303c4a03, 0xda1980c0a597dd0f, 0x2fddc599df0832d5, 0x10090314b014c0af}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9af98513b8fa3e32, 0x76a99773a39804d6, 0x49ed6650bc0128d4, 0x34fce51deddd27d8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x29ccc4a9b0c2b010, 0x8a8f514b705229fe, 0xc1e6d12b311256f4, 0x3291611fbb2fab1e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcb4ebbb08bdb9c9d, 0x744ebe7f914218fb, 0xe77c5babcec8a686, 0x2d42a41428a90175}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8ec3d97ab5616a9e, 0xe8014e7c1141e6ff, 0xa8daca3054309538, 0x1c08ef18d73c76fc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcf92950eb4f3789b, 0xaaa450f22a280bf6, 0xc9e4a80c9f2cd996, 0x27f4ac96508752f6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7bbd2ed16a76edc6, 0xd8e2186c7de847db, 0x2aa88a2b65118dd0, 0x1c55b5f615dc28ea}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7ccf57f28acc118a, 0xf5d3c6eb14e65154, 0xdc079fcf442a0f54, 0x11993cb931932e5a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf76b4a8906e70667, 0xda7f02e1bf4e36df, 0xaab6b7f1de20dd0f, 0x19fc46ff2ddb173c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3a3d2dc8cc132eee, 0xf357bef4e1d3a63c, 0xd48a3a0eb2bc1415, 0x2bc75acfaee9db1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5fbb66b806674243, 0xf73af3e558a86209, 0x5d30fbb40ede547c, 0x501e03ee293fd1d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe90568a8237171ac, 0x650fc27c4da7f2e3, 0x546a3b7012993072, 0x87e3d6d0e54850d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd5dfc1afce8127cb, 0xc6874ecb5b959056, 0x17d19ee832e735c7, 0xbf09138a8fe4ccb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x489c20a8f79b4f58, 0xaa9a7c84d23aedd3, 0xb66eddf614963ee3, 0x2dbf9ab7c2343a43}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3dfd42b46f1e6946, 0x58f29edf399435ba, 0x2521d4287bc79d64, 0x1781fbca8872f93c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6d6aed7cb045289f, 0x44132433ac541a78, 0x660c1badd4c7e0de, 0x30330b4022cfe5fa}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x31b90687198ee938, 0xf9b1217c09a47868, 0x1df6bdd931eb2b30, 0x151f40cfa7ce6982}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9049df43bd2b446c, 0xc117a3d9f6656367, 0xfd356803d03495d8, 0x200e3c9d4c1b8eb8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x90d2cc13778a0928, 0x9b7d207f836f7d68, 0xac2d328e8bc0cdb3, 0xc70770d5c26e2ae}},
			},
		},
		mdsMatrix: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x32f4f94379d14f6, 0x666eef381fb1d4b0, 0xd760525c85a9299a, 0x70288de13f861f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ab57684465d1ca, 0xf12514d37806396c, 0x825085389a26a582, 0x308efdddaf47d944}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1b2098a19e203e93, 0x914dcdea2a56e245, 0xc64ed9aa2aef8379, 0xb176f95c389478e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf895153087f5dca3, 0xa53543f74c7e98f, 0xf5a0b430a14b8c2d, 0x6ae54007a872b0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfd0c32f86be981dc, 0xf60dbc5c1bd0b583, 0xd4f3f8f9a2a4537c, 0x1d71b70d52f42936}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8f85e752c76f7c9c, 0x8297f4f031b02763, 0x30e4ea62df5067b7, 0x2821d0423006dcae}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5cece392cc5d403f, 0x123da1ba8becd2de, 0x193510960c81a54f, 0x1be17f43c42fe5c0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x65fc36e3c120e5dd, 0x51a4797b81835701, 0x3123b2b88ae51832, 0x19f174900d86138a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6d0db66a74936d4b, 0x1b8aa34d8d4554ad, 0x8605b5c1a219423d, 0x3055d8d876253885}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9b8b22118b0179db, 0xe14da53ccd481770, 0x109e7ae5ae61278d, 0x13cd85bd55c2f52e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd03df46130dd77b4, 0xe694d8c7d8fd4ef4, 0xf71d2a65470713aa, 0x255c475344778d2c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x78597119a27f97bb, 0x1b1fb7c15ccb3746, 0xb86d8ab32d6a6edf, 0xb1e00f75148f670}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x875597b15bf7ed8d, 0x73fa4e676bb9cc5f, 0x96babdc32ae359e, 0x31e6d9f5ccaa763e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf27e0f92236fd303, 0x6e607a16f84adab, 0x4cc8addf91894557, 0x1fb0a70aa0f1061c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfd2a420b19b31725, 0xddc5361119d53b6e, 0x3d58af3f6737f156, 0x1350a7bb521c58a6}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf88f2f863cb9d6fb, 0x5078f8e89e8f9ff9, 0xc5583fcea6176010, 0x25e363acdb694459}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ece0c297d2f49a2, 0x9ccc88a13c91abae, 0x4138c965288c3d87, 0x437768eb72dfb4f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9fab22e085f93fe5, 0x63ca08a361b7fb0d, 0x7e9790bf5bd5837a, 0x6080ada873c8216}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x32d3b34d8c43a402, 0x2c7e5748fb940669, 0xc0a36e42a28c6f80, 0x24ac3e6b181bb185}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x470f7d02d1dae46, 0x8cf3cde540035d00, 0xe3c0216f8d5d807b, 0x3e3e8312ef71fa39}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6682f4469913559f, 0x3b053e58dc4560d6, 0xf84c58444b5bdccf, 0xc3230d834c17967}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbff2a45de17e9da7, 0x6309bfdc8e152f51, 0xb9ae2f9af1f30a1b, 0x27a8797c59f97b06}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd787c4dd405d1b3f, 0x7da8effab83f1842, 0xb3f8303ad313dac2, 0x3a1a7a3002e72833}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x327b7f748a0695fa, 0x7dde58a92f496b95, 0x8a02b6088016449c, 0x1cef42b151422c3d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb22ffb451127fa1a, 0x3c17ca7183462744, 0x4de2e19b12854d65, 0x20938ee131fc7ef0}},
			},
		},
		spongeIv: [][]*native.Field{
			// Testnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x63d01a5eb2171352, 0xa156f498468c138a, 0x6863ea2849c3a1a2, 0x9d3a988f1f410b1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7102a042f3032c7a, 0xec792d3bae28c836, 0x56ca8c6f048bc984, 0x1219b5fcf34e0a1f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2ac12e04eb8f550a, 0xa5757bca84777f2b, 0xd3c2bf917b1192ea, 0x1989968c7935c607}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe1d62db2c86caa07, 0xb8ed617d8704c6b, 0x4e71934f60359a00, 0x25459aa434d50ff}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x290a6ff9dd02df5e, 0x6e4c26ecf7984888, 0x8f5fb54612793d95, 0x31404beb90f0fdc8}},
			},
			// Mainnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1bc46288607092ee, 0x679d1013fcd27af4, 0x2302588441a00b35, 0x52aa4180a0e1d3f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf44d99f5d1788e7c, 0xa808f4bc1c5e8caa, 0xd3fd8806f5f3de6, 0x12ad0b5be60d68f1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6928c9d83855c9d, 0x4b93a3d0d8209f22, 0xbbaea51d0f1f12e6, 0x62815b7ee55e6a8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1fbd2d82dcfa2d, 0x78ec7156c609e43a, 0xf1e203a769275642, 0x3e15c2753ca6c1d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6299f39409f35a31, 0x279b391979868236, 0x87b62f1b72d1deea, 0x3b44d1afce3a530d}},
			},
		},
	},
	// three
	{
		spongeWidth: 3,
		spongeRate:  2,
		fullRounds:  54,
		sBox:        Sept,
		roundKeys: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa7eaec68b00f442f, 0x6f59e1a835643145, 0x5e1085dc39694ee7, 0x31f43b11041ce57e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xaf9d994fe02cad85, 0xd023d4dba24251f2, 0xab2b289011b10b15, 0x136703f8461e5900}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x17d4dcf1505a5b8e, 0x905301ba46f35eda, 0xbf183c861c890269, 0xcd2255c8e8bfad7}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x652519f35396e7b9, 0xf939da87dd2565f7, 0x77863388eeb1739a, 0x2ef0165a2c2e5844}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x477f697921c5a46f, 0x2f5597aaf22a3c0e, 0xea51d9a2b20ef8ee, 0x27f19ea80ac259a1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x475253132eafc552, 0x691f153f119e2158, 0x3463b3d75dc73170, 0x3875a2611a0025e4}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc1500848eb7005a6, 0x61e2acd1faf26ff8, 0xf50c67341380fa2f, 0x14e95cd68d6778e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa82b34cad0ebd99e, 0x771d54af176024ba, 0xa343788ac43bbde2, 0x31c9ab354d21b72a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3deb92a1d0140aab, 0xb710f83bb2ce1349, 0xf3dc159cb9171a97, 0x6c3eac66a23c368}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd25cd659b62b584, 0x3a52d26b8092be14, 0xe36c5155d1e135b, 0x16deeee5467c7a70}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9b446f453cb50aca, 0xeadf51c8f0af7a58, 0x75da6f44c4a04ca2, 0xccc39a8549cb487}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe09191801b0fdabc, 0xa7452c89066d4bd0, 0x5244883ddc1fd9cf, 0x3862cc172ab37d2f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6a87a9921ce9aabf, 0x5d701ed9a030bc04, 0xf99642aa2a835ec8, 0x28319fcffc61a144}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xafb8a54d87a15b37, 0x31e93428debef477, 0xd328f47b48852d58, 0x1e9fb7a3f8c8e39f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa58f9aa995fcab1, 0x5fb0135046864286, 0x6ad292753e09ec37, 0x24cb4d2ff2e77907}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbebb7c8e57280d90, 0xa2575331fa3f83b, 0x1bdaa15abc6032e4, 0x137f4d26f7fc2b89}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8ea04d93f2a3faba, 0x76d83e0976143e11, 0xde45171e6c479b69, 0x3ec500ad89afdcfe}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9741b7a395379855, 0x916b939a142e1e68, 0x4fda77496b815109, 0x19d993fa47fbc1a7}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x31d6e313b491fe95, 0x19f07f1a489cb20a, 0x517ac8eb07d91f83, 0x16bd2c0e204bb5dd}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x42170b694f7b1926, 0xdde594e9f6060540, 0xbdb7c66abef575a5, 0x26c2c710d9aea3c9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xccfb5e566332e76d, 0x4e73df588d423339, 0xa4ede3fda7178916, 0x28fc0255accddbf0}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2fc2f7a5cf4eeb76, 0x709a30d94daa56c0, 0x67a5dd9c696533dc, 0x3ace056f839007b7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7769ae0082cae71b, 0xdaa4d4c08c74011a, 0x919a01423e32424d, 0x22467d425c99d5c9}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6bcd3613ace4871c, 0xb0bc217531069def, 0x55348199fa2b487b, 0x2385b602228e77ee}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7022e34179f7fd32, 0xd7d122a3a91838e2, 0x20e0714f41741103, 0x55ca30203c35d65}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xeac64a4e27a532ac, 0xfad717669ae09d08, 0x16088f7d30d724f1, 0x37bb5a0c062e6400}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7c34a314bcba4635, 0xbfdd1e4cda8ce53, 0x7b9809bd9828ebbb, 0xbe17455fb915f02}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3eedf4d1439104cc, 0x6944849f8d44d187, 0x4dbe80e8f415dfdc, 0x1df9173c6d047e75}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbe0b090e46076c2e, 0xdc964a5825b49df4, 0xc8c690008b31f4cc, 0x2a7eea60cbe9e9c2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7e3ea7d6debb93ed, 0x697818afff9c8ff8, 0xbd716ed0d057327c, 0xb4a53cd8838ca03}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9249570785f595ac, 0xa8baedefd054d755, 0x4e349f30983cb2d1, 0x20e038ae5219f06f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1e6b0d84b6b0bd2b, 0x28036e399a182d83, 0x9b4db5cdc8f5900f, 0xba7d843e40009}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc1862aa768e1a9de, 0x134ee89ea258d84b, 0xa344c6a98af5c8e1, 0x35868f24584f89c0}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6562561d6d2bd2eb, 0xe906eab7bfb25ce1, 0xdc3286360790ca24, 0x95cf9864fa2e99f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8df04360bfee0f49, 0xf36da4b0797f28ab, 0x973b5df087ce6868, 0x31b4ebf5790f547a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5236c69070d6a6cd, 0xe3483908bed7cd3a, 0x230cf521e8f636d5, 0x1369fed0b1ebdd4e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6b84b4d8a249ce56, 0xf8f9e37aee88a381, 0x547e20f39ea3ee67, 0x1a521535f4c4609a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xece3e35b95cf0b40, 0xc3f355a2343a9bba, 0x352dca283e1dc20, 0x18533c495c159ea5}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5c080eb0e667f655, 0xae7eedb84aaa82cf, 0xc40800efbbfb36e2, 0x23f8f08e412d848e}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe47de2b666816c07, 0xfd084e96b59c227a, 0xffee4cb4adefb5b9, 0x27873596008bf329}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x74c07063640d932f, 0xdcafa7d16923f8c6, 0x69cc607697b5fa58, 0x3fe8dcd350f158a0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4685e7e0534a4487, 0x3e0a5a82c1308413, 0xe8f4882500745f38, 0x15d7152e439e3e39}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1b6a574d8750bc73, 0x106eecce46abf1e6, 0xaac26d11ddaa2fa6, 0x38e31bc0f50b77a8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x46f4e9b5d03cc39d, 0xcc3f83cbed376830, 0x9b08a2cd1eb3c25c, 0x1b205334b2958429}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd58f58d5f1219de9, 0x1cfaa7547a262198, 0xcded38f37a2a880d, 0x177392b21a898be2}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xabc2d6caf40fda5a, 0xeb350f697f26ad45, 0x3a8945142b944356, 0x646f6d15a42f200}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xff43256a693e8ab0, 0x2d305df7c836dcae, 0xccde78bd165aba3, 0x784cf8c1e09fd03}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x11c0a75dfb1d6922, 0xa7dc5f890e8b9385, 0xaf784b2ec0758e11, 0xb79376b50d40562}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4cfa43b93f239b43, 0x8465e6265d898268, 0x1288bcdb6fff50f4, 0x819462af6ba8c78}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xba07b8ffdba328b0, 0x4215ac492cce28b3, 0x9730ec3e2f2188f3, 0x10bc9871d3004f71}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5a31626caca7283f, 0x40424e694cc63e9a, 0xcceb1adc2a52c6b9, 0x2836d9e7ccb5b686}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf2191ab8935e3139, 0x6263e421438839a9, 0xf36d5611a925964c, 0x3ad254981c5584f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x77f3cbe4b7ec0506, 0x14cfd27cad91e7f6, 0xd66382bc65d30343, 0x11eb1499a7eb9296}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8306372b9fccfce6, 0xff3f90b389214f3f, 0x589837150e5e7261, 0x330673584db884bd}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbf438550dc08ca8c, 0xa67d5b92e6b2d9f4, 0x45f1b4851f11355e, 0x3197089756209bf0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa7bb2e56a3383876, 0xa1b85198d1a992d9, 0x807a2bb7e34327c6, 0x1a7be86ebc9ceb25}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb67db6d33a48b0df, 0x20bcebe6769fcc54, 0x2c5defebf8a107df, 0x3c0e75597f21e444}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3ee09fdbfc3969f8, 0xfa1d3b39ae852fe9, 0xf9a75fb275dc4bf3, 0x2a38ad56c662e4c3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x436111724d967633, 0x7bc3452ae208f145, 0xfa8b9c79a56e7177, 0x3328b53b61a96c1a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7dc685041c4a8de8, 0xcc8d3bf1000d5962, 0x53f0f1b8456b9659, 0xe5633a4ee33b43f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x50e48fb72f31229f, 0xa5b753a3355553ad, 0x1c81ccd682c6dbf0, 0x6c795d332f94020}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf0fdbce25dad3d31, 0x9c588e128b3cebf0, 0x278767bad1a401ec, 0x12fd7107dacf168b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x98f200455814ae5c, 0x47f8009a5ae445bd, 0x487393e3ebc8077f, 0x3d579e85ebce0cba}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe8df711446a2a238, 0xde4cc56b9510c04c, 0xb69991b66d096631, 0x1ab962f474f31f94}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x994397076df00b58, 0x655b22de2fc1d376, 0x8c4152fcacaf0b18, 0x20051bcd8c1c3f37}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd66fe84e8d8d5bcb, 0xba022f54bb73200, 0xdaf17b9ad85c1d89, 0xd939c085418afd2}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd5e63b74c211bc, 0xb12fc9c1def2e171, 0x44eaf0fd6faad3ea, 0x242c8eaf5e3f8025}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbf97706088f0ff2e, 0x1d8dad8a65750bd0, 0xc29b958d06fc399f, 0x134e81757cb8421e}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x90be439afe7faf2, 0xc4b4762c8cc16bea, 0x1e477be4c4f40c9b, 0x23b4d50dc7ec40d7}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x333f64ebf7d2e7a8, 0x870b1f5dbdb11bdf, 0x74c9542dd65f4221, 0x128bb297ac5b8087}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x74cdc264c1c32632, 0xcdbd7f0678ca09f9, 0xeb378a38bded711e, 0x1c4c18ced367bb10}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x436cf961456330a9, 0x5261fdb10401ba02, 0x5aa07cfe8724969b, 0x17d4aa22d7539f30}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x22577a304a9a99c0, 0x26990766bceeaf3e, 0xf44a18d2965b75e6, 0x2b9ccb511447556b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb4816bee4c57ea14, 0x657c7ff22284eddf, 0x80327f4b561a57a, 0x185d288b2163e408}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2521ae71bb3e92cd, 0xcfa6a3908f9422a4, 0xc5566b5d0cba3b6a, 0x19186ee34b32adf1}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6ababe0d83a14804, 0x48a2976613fe9c87, 0x8fd28b1e6637a35f, 0x36be57a5b7dc101}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9409b310f8dedbd5, 0xdcb6ff2dd7ade6e8, 0x58ef424bfb1e96cf, 0x59c25a9e8435caa}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6017336865718144, 0x3b735147994d3174, 0x556dacb8916ce5fb, 0x6db68d040cf3894}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfb28daa548eae196, 0xdee9f1fb48ad3a18, 0x8aeb7ea74f7458e0, 0x2f9a904f8eca76f4}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x78ab93c53d27c0a9, 0x7cbd38a19659d91e, 0x6190fc4c6fcea287, 0x392493ffebdcf4db}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc288a18be7c7b29a, 0x293635495be4702a, 0x8eabeaa050c4e742, 0x3ee20e43c9a7e3a9}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb247c20bce94d2fb, 0x7b37f102aba6dc41, 0x4e4cd6f2dfd06908, 0x2a4b7450c10e8656}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb8530701f1190812, 0x8852c8a7dd78c157, 0xef99612848a09ee6, 0x18cac72301419e17}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3bf72719696125f9, 0xa9153cf6b92ed66c, 0x5dee1004fa68e8ad, 0x2b0ab9d9c7146b8d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x536e86c644632835, 0xfb528949c3d10378, 0x93cef66ee69cc174, 0xef7cc63c029b540}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3f71db10b88e45e1, 0x6a1cdfba155d75ba, 0x3ae6893f9c00830, 0x1f4aa1edaeea25af}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6c911d68b8bae9c7, 0xb562eb9132f9adcf, 0xb99552efd2922e09, 0x1aee619f6e53e5d1}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc3e7eba538b57ce4, 0xe31fc856b301a0ed, 0x907bed9fd07a7f39, 0x2d8b156182efe6c2}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x3c46848a7286379b, 0x8c1ce4abf2bdac01, 0xfe59adadfa57ab2d, 0x118d842df28ba098}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x40346673db347d50, 0x9e9e286fbc221bac, 0x629f295d0d56a062, 0x2c7473af62ed3627}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x752c0e54b9084c5e, 0x9876503df35123f2, 0x4033dd4b36b302eb, 0x1f2f3ed1fdf6db7b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xc1aac2892f6ad5a0, 0xa4d2c62a12460d75, 0xfdfc27280cba16d8, 0x32e7b499b5afa89f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa93b9c721205117, 0x29f32892dd66377a, 0x5db34e58446659b5, 0x35b9a957235ce56c}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x27dd8772ea8dd6fb, 0x7657580893377a80, 0x98116540d5d734fc, 0x1784ef3dbedaa7f1}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7ea4b4453558ad1e, 0xe79ae8a84479841f, 0x1448d360ba9dceaf, 0x29004bf2b27c1cc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9be743f9caccf63, 0xf852240a936f7e9e, 0xb1cd6029e13842dd, 0x255bdfce8905f3d5}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7415ee9f67631e70, 0x545553ffaf7d2592, 0xde51ae9194c9a7b2, 0x304409b176b5751d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9c447ba5504d7b34, 0xfb288ee73506db89, 0x4cb32cefbc235f79, 0x3f2084c1c1605185}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdd24109730f8173c, 0x58b00f316d07a773, 0x1e86bdb19d121999, 0x3c46e8c04c88a74f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9ff193f33610856, 0x7cff32dc29fafc7f, 0xab1176764a90b2b5, 0x37a314e9261a12bc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xea6753fdcff09509, 0x4222dd5e1a66381d, 0x6056412c14d4667e, 0x30f19d0141776609}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x383a756cdd6bbf4a, 0x4b314310043c1039, 0x7aa6b018a79ad7a4, 0x2d78d62918aa8e15}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2c202fafd61e9da3, 0x89be41afc9c1f1fe, 0x15b6d718ea74a2d, 0x1c1c7eb84e510588}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x342bbc7354bde7a5, 0xc995adfbe2005f6b, 0x85a618fbe9ccea3c, 0x3d61c03132b831b7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x84f0053a596c462a, 0x3725a512ef2e7da, 0x9866bda3e8d65025, 0x16307f53c31b9b2d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe11a11d7ad7c2941, 0xa196efe53885dac4, 0x401c98e5702a4b4d, 0x2627aedf841d2535}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6c137315f42a3d7, 0x1b27880c4b80acc2, 0xd2463e7af19c63f8, 0x1ac361c3ae9360d0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9ca7acb3c1e8764c, 0xa3abf95002b63ec7, 0x607aec3d66927bd, 0x350322d135e4b5b0}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x8767a56f58823fb1, 0xa17115bf335777f7, 0x2d2d011c09bc4b6, 0x23f5c30c8bec1802}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x469e5aee1e354cff, 0x19b662c5ee659a15, 0x8222b7d81ef2e3d0, 0x25dbe21f1dc14bbb}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcf3036e9bef51413, 0x2ec597011f15b75d, 0x1b6f15cf41987ffb, 0x243e4331eaa8ca3f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7e12d7264aa9d64a, 0x986866249a40df19, 0x224d9731f988d510, 0x3da1029b04d0699}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x63ce9c82f26c2122, 0xd07b42737417e607, 0xdffe6c18b3e32c4e, 0xcb558a55e33635b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa9e72e1bbb1e1ac6, 0x7c0eac490aa84fe, 0xc716b352d91ef297, 0x17c0df062139a3b0}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb6e0e5acafd75f1b, 0xe79ccc9d178be022, 0xa62fb84a4594821, 0x118ff23cec0e9ab7}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdaeb6bb9649cc9ed, 0x2b1c328f5bb8662f, 0x5512487ef834c9ff, 0x10a6d8b760d8381f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x55bcd8a0925661ee, 0x92289bf6cb46afe5, 0xa2b1c38630374b57, 0x1a382c83ffa7d479}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5b9ed41d83b22227, 0x861a12cf34e20309, 0x722187ecc9fb01cd, 0x3d7bb8d8fbbf19aa}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x56b2351caaa77660, 0x5649f8afb77f8250, 0x179b134befc40c2a, 0x117b5ac7fab8a73b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xbb53d76efa39fb63, 0x3821ad8ab6648b10, 0x860e686568c98df, 0x181510039e8bf016}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xabcab07505b93cf, 0x4088c208ddc38a79, 0x60aa91fcf3d30a95, 0x1cca89ba50887f72}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x756ea77ac464fb2f, 0xb54ae17c6bba044a, 0x3350ae0df3e90873, 0x186b9034baedae26}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x813cc8de3ccd6501, 0x612bffa93d7579f9, 0x5ad42ea9bc5bbd6c, 0x123ed625db167d32}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x2db34a3c43a01e76, 0x93bf90bd39919618, 0xb62aafc5a062e6ec, 0x30e33d44bc2851c0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x74dcd4e07d98a23b, 0xb390d88ce8c1c12d, 0xc60d4855592f4f12, 0x3d3808ea888bc3ef}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x6b6125132d3b6c9b, 0xefb93b37d8c98901, 0x5396ab9879f061f3, 0x26814970d99a4859}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x65a39dff4c093ac6, 0xdb8b03741b7d38b3, 0x34e5285eb2732099, 0xcffcab13b9c402}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xba151ecf346e77e5, 0xdc944d4cedf21de6, 0xbf6157bdc8bf2df3, 0x39a726986b4d3042}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x44150981f7bb214f, 0xdaf82667aa9df080, 0x4cb0e4251cbd837c, 0x96407a7f4c8919d}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xab327a1874a4376d, 0x2ac8b215b83ec21, 0x72ccc1310e756e19, 0x337f64158d29681d}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfdd547b12cd1c47c, 0xeda570d77efb35ef, 0xee673a9c5c5c6c24, 0x1069938e1c2d5fb8}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe18e30b72b41cebd, 0x9530ddc35a81e36e, 0xcb076c0372dd1f10, 0x1a6810a2f1aee9a3}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf42b4184e45ef9b0, 0x621c9c9f4b7805bb, 0xe64a4966c57c625e, 0x331dfaac4fca1afe}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5745585e5aa8e18, 0x48138c500616daa7, 0x740880dd14d57c7b, 0x621e4237f79bc67}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7752004d293d5b5d, 0x32176da95d737cf5, 0xe14bb9ef4281cf03, 0x56e679688dec9b0}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcf96c57a6c6dced2, 0x9d0641008bc1e8e6, 0xaf7c8a61f00aea43, 0x3de7cc921f006f35}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe5a284274906c87c, 0x3f57a5c227ad9ef7, 0x8ca3d4e109a701b9, 0x23fa54fa0717813}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa418bb283bcf6e4c, 0xfe2037c5295b505d, 0xcaa0956e946f4a29, 0x2a042a0cc94e6eb7}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd8df14778b795fec, 0x16c27f664e2ea362, 0xe24b2f6edd5eaebe, 0x14c903e18d6d1fc3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x89586ac5b4450805, 0xadc6ee91f14ae921, 0xc6bc4c3b0f873a03, 0x351fccf49d14543a}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd3601422d37aaa9e, 0x988c203077dd68e9, 0x1cae7a1d3150e958, 0x1292d11437a1acd4}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xe53e955d71efa6c, 0x8fe1b41936d8c2e, 0xc1115be6796700ba, 0x16f2577444f333ac}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb46fdc6c76b91715, 0xba7c98748d26f41a, 0x8a767b731b64d9a2, 0x380f78e27ff89d8f}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfd9976c4488e5f16, 0xbeaf3cb1cf0cfc03, 0xf2bc02883a339b2a, 0x3a669a9fec53277f}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x7489c5648c85dee1, 0x7f9d020bd71f0bc3, 0xcf347020818fd255, 0x34ce3d2873ef623b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x82891abb666f3ff4, 0x370d13492155070d, 0x26c0426048d99ec2, 0x89cceef0d956cc}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xf161875b3c921a95, 0xe0ee4bd7518d961a, 0xcd3614b6acaf6d93, 0x27ef7c723667b755}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x13fb2dcf933fd4d, 0x103f7deb9f64a5aa, 0x26d375314a7a8189, 0x1fb433f9d0d1a1af}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xa49a8d2583ef3bdd, 0x9a7a627ea2417df1, 0x93277db6c1298ce4, 0x224efdd22b53fe03}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xd9ef2ab6918b48ed, 0xab7f9a26705488c0, 0xc179467a22565381, 0x3c8192acf2659bbf}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x90c3c01685741695, 0x8fc7d42cbdf62efb, 0x8ca74bdebec3a42b, 0x2d07192135436805}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x597f91232510722, 0xb6ff30a1505c4ea8, 0xdd22fd456a942afe, 0x1cb7fdcfaa9bdd05}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xdcf520384f1ddaf0, 0xeb0ee12c33953a63, 0x9a3a10c7e3aa6f41, 0x1471506df8d986b4}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcd605e2791e6a5e5, 0x1c27ce94b83f068f, 0xb172e53c549a3c12, 0x21f264ce80eef855}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xfe4a5caf09cd178f, 0xd76b6393a8b8597f, 0x828a31309599f1fa, 0x1d7eb56ca9c920f6}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x589bdbc5eb3cc1fc, 0xa5ab6823129a3ed3, 0x1f5b9bd5aca5d3ec, 0x64aae35f2e4b6bc}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x365002f75230793, 0x2b8d834bd6a4c78f, 0x7f445a46d203a93d, 0x265c579246ab3106}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x4983fb4db3ca5acd, 0x770c07654eeefaab, 0x54456b57fa1fd5af, 0xb92cdbcf718c353}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1ac57ac76f928fe, 0x816c4d52b670680, 0x39b8598cba83c07d, 0x29af1b8a7d9ed796}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x715eb17f6f71404f, 0xd081dca0cad01695, 0xdeefdf16929d4947, 0x3d7f767198a2e29b}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xebfb13feb0205761, 0x73e014ef38a3d8cb, 0x113bd31d16c16db7, 0x288eacb7eaa4d63c}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x5d22751f1f2c937d, 0x50cc30867fe04f68, 0x70917ec415d4ac2c, 0x58c8b7c2b87e78b}},
			},
		},
		mdsMatrix: [][]*native.Field{
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x19ebb0733ab608d5, 0xba29ddd056f8255c, 0x90b26832e301952d, 0xd393e38c7a5d0ab}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1370915e16c94656, 0xa9d4f14bbd2ea831, 0xbe629fe93a27e612, 0x21571a7cc32e18af}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb34a71b4f799ea19, 0x9685275173ff9b6b, 0xc2aa354b7f11d698, 0x15691c24c0a9f088}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xae932a9d486aface, 0xbef0293e7653db35, 0x279408c4d244c0d1, 0x39dd8040ea0c8d80}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x9d32fbdbaf9bbe27, 0x999e1c5168806efa, 0x7d5f270b3cb077a8, 0xb4ac0738805f8de}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xcfc1e61e0bcf9d5f, 0x12346d0d47576a9, 0xdbd1b0da710c7b5, 0x1db48905ceecc479}},
			},
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x89dde65da2c627b, 0x873534c4aaf1243a, 0xa4f76bf3e5b626c5, 0x22a75f7cd3cad9d3}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0xb58ea56557361c3b, 0xd6cbb2cb0bc99acb, 0x5fee1fb5b71b86dd, 0x11d87bbca8e20fbe}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0x1d511fe638baa5c8, 0x7b6c7932776e1032, 0x45b27ee070531360, 0x19eb7c902ac90c5}},
			},
		},
		spongeIv: [][]*native.Field{
			// Testnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
			},
			// Mainnet
			{
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
				{Params: fp.GetPastaFpParams(), Arithmetic: fp.PastaFpArithmetic{}, Value: [native.FieldLimbs]uint64{0, 0, 0, 0}},
			},
		},
	},
}

func (ctx *Context) Init(pType Permutation, networkId NetworkType) *Context {
	if ctx == nil {
		return nil
	}
	if pType != ThreeW && pType != FiveW && pType != Three {
		return nil
	}
	if networkId != TestNet && networkId != MainNet && networkId != NullNet {
		return nil
	}

	ctx.pType = pType
	ctx.spongeWidth = contexts[pType].spongeWidth
	ctx.spongeRate = contexts[pType].spongeRate
	ctx.fullRounds = contexts[pType].fullRounds
	ctx.sBox = contexts[pType].sBox
	ctx.roundKeys = contexts[pType].roundKeys
	ctx.mdsMatrix = contexts[pType].mdsMatrix
	ctx.spongeIv = contexts[pType].spongeIv
	ctx.state = make([]*native.Field, contexts[pType].spongeWidth)
	if networkId != NullNet {
		iv := contexts[pType].spongeIv[networkId]
		for i := range iv {
			ctx.state[i] = fp.PastaFpNew().Set(iv[i])
		}
	} else {
		for i := range ctx.state {
			ctx.state[i] = fp.PastaFpNew().SetZero()
		}
	}
	ctx.absorbed = 0
	return ctx
}

func (ctx *Context) Update(fields []*native.Field) {
	for _, f := range fields {
		if ctx.absorbed == ctx.spongeRate {
			ctx.pType.Permute(ctx)
			ctx.absorbed = 0
		}
		ctx.state[ctx.absorbed].Add(ctx.state[ctx.absorbed], f)
		ctx.absorbed++
	}
}

func (ctx *Context) Digest() *native.Field {
	ctx.pType.Permute(ctx)
	q := ctx.state[0].Raw()
	return fq.PastaFqNew().SetLimbs(&q)
}
