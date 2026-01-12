package aqua

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAqua(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aqua Package Suite")
}
