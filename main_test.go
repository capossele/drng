package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/pairing/bn256"
	"go.dedis.ch/kyber/share"
	"go.dedis.ch/kyber/sign/bls"
	"go.dedis.ch/kyber/sign/tbls"
)

func TestTBLS(test *testing.T) {
	var err error
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 50
	t := n/3 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, err := tbls.Sign(suite, x, msg)
		require.Nil(test, err)
		sigShares = append(sigShares, sig)
	}
	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	require.Nil(test, err)
}

func BenchmarkLagrangeInterp(b *testing.B) {
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 50
	t := n/3 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, _ := tbls.Sign(suite, x, msg)
		sigShares = append(sigShares, sig)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tbls.Recover(suite, pubPoly, msg, sigShares, t, n)
	}

}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 50
	t := n/3 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)
	for _, x := range priPoly.Shares(n) {
		sig, _ := tbls.Sign(suite, x, msg)
		sigShares = append(sigShares, sig)
	}
	sig, _ := tbls.Recover(suite, pubPoly, msg, sigShares, t, n)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bls.Verify(suite, pubPoly.Commit(), msg, sig)
	}
}

func BenchmarkSigning(b *testing.B) {
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 50
	t := n/3 + 1
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tbls.Sign(suite, priPoly.Shares(n)[0], msg)
	}
}
