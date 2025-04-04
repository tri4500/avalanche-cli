// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package subnet

import (
	"github.com/ava-labs/avalanche-cli/tests/e2e/commands"
	"github.com/ava-labs/avalanche-cli/tests/e2e/utils"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const subnetName = "e2eSubnetTest"

var _ = ginkgo.Describe("[Subnet]", func() {
	ginkgo.It("can create and delete a subnet evm config", func() {
		commands.CreateSubnetEvmConfig(subnetName, utils.SubnetEvmGenesisPath)
		commands.DeleteSubnetConfig(subnetName)
	})

	ginkgo.It("can create and delete a spacesvm config", func() {
		commands.CreateSpacesVMConfig(subnetName, utils.SpacesVMGenesisPath)
		commands.DeleteSubnetConfig(subnetName)
	})

	ginkgo.It("can create and delete a custom vm subnet config", func() {
		customVMPath, err := utils.DownloadCustomVMBin()
		gomega.Expect(err).Should(gomega.BeNil())
		commands.CreateCustomVMConfig(subnetName, utils.SubnetEvmGenesisPath, customVMPath)
		commands.DeleteSubnetConfig(subnetName)
		exists, err := utils.SubnetCustomVMExists(subnetName)
		gomega.Expect(err).Should(gomega.BeNil())
		gomega.Expect(exists).Should(gomega.BeFalse())
	})
})
