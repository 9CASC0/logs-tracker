package merkle_test

import (
	"fmt"
	"testing"

	"auditlogd/internal/merkle"
	"github.com/stretchr/testify/require"
)

func BenchmarkTreeBuild1000(b *testing.B) {
	leaves := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("event-%d", i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = merkle.BuildTree(leaves)
	}
}

func BenchmarkTreeBuild5000(b *testing.B) {
	leaves := make([][]byte, 5000)
	for i := 0; i < 5000; i++ {
		leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("event-%d", i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = merkle.BuildTree(leaves)
	}
}

func BenchmarkProofGeneration(b *testing.B) {
	leaves := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("event-%d", i)))
	}
	tree, err := merkle.BuildTree(leaves)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tree.GenerateProof(500)
	}
}

func BenchmarkProofVerification(b *testing.B) {
	leaves := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("event-%d", i)))
	}
	tree, err := merkle.BuildTree(leaves)
	if err != nil {
		b.Fatal(err)
	}
	proof, err := tree.GenerateProof(500)
	if err != nil {
		b.Fatal(err)
	}
	leaf := leaves[500]
	root := tree.Root()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = merkle.VerifyProof(leaf, proof, root)
	}
}

func FuzzMerkleTree(f *testing.F) {
	f.Add([]byte("sample-event-1"), []byte("sample-event-2"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		leafA := merkle.HashLeaf(a)
		leafB := merkle.HashLeaf(b)
		tree, err := merkle.BuildTree([][]byte{leafA, leafB})
		require.NoError(t, err)

		root := tree.Root()
		require.Len(t, root, 32)

		proofA, err := tree.GenerateProof(0)
		require.NoError(t, err)
		require.True(t, merkle.VerifyProof(leafA, proofA, root))

		proofB, err := tree.GenerateProof(1)
		require.NoError(t, err)
		require.True(t, merkle.VerifyProof(leafB, proofB, root))

		// Deliberate mutation must fail
		mutated := make([]byte, len(a)+1)
		copy(mutated, a)
		mutated[len(mutated)-1] = 0xFF
		mutatedLeaf := merkle.HashLeaf(mutated)
		require.False(t, merkle.VerifyProof(mutatedLeaf, proofA, root))
	})
}
