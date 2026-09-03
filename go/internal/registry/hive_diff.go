package registry

import (
	"fmt"
)

// IndexDiff is the streaming merge-join result between two hive indexes.
type IndexDiff struct {
	Added    []IndexRecord `json:"added"`
	Removed  []IndexRecord `json:"removed"`
	Modified []ValueChange `json:"modified"`
}

// ValueChange is a modified registry value with before/after.
type ValueChange struct {
	K  string `json:"k"`
	N  string `json:"n"`
	T  string `json:"t"`
	V0 any    `json:"v0,omitempty"`
	V1 any    `json:"v1,omitempty"`
	H0 string `json:"h0"`
	H1 string `json:"h1"`
	S0 int    `json:"s0,omitempty"`
	S1 int    `json:"s1,omitempty"`
}

// DiffIndexes merge-joins two sorted gzip JSONL indexes.
func DiffIndexes(fromPath, toPath string) (*IndexDiff, error) {
	a, err := OpenIndex(fromPath)
	if err != nil {
		return nil, fmt.Errorf("open from index: %w", err)
	}
	defer a.Close()
	b, err := OpenIndex(toPath)
	if err != nil {
		return nil, fmt.Errorf("open to index: %w", err)
	}
	defer b.Close()

	out := &IndexDiff{}
	aOK := a.Next()
	bOK := b.Next()
	for aOK || bOK {
		if aOK && a.Err() != nil {
			return nil, a.Err()
		}
		if bOK && b.Err() != nil {
			return nil, b.Err()
		}
		switch {
		case aOK && bOK:
			ka, kb := a.Record().SortKey(), b.Record().SortKey()
			switch {
			case ka < kb:
				out.Removed = append(out.Removed, a.Record())
				aOK = a.Next()
			case ka > kb:
				out.Added = append(out.Added, b.Record())
				bOK = b.Next()
			default:
				ra, rb := a.Record(), b.Record()
				if ra.H != rb.H {
					out.Modified = append(out.Modified, ValueChange{
						K: rb.K, N: rb.N, T: rb.T,
						V0: ra.V, V1: rb.V,
						H0: ra.H, H1: rb.H,
						S0: ra.Size, S1: rb.Size,
					})
				}
				aOK = a.Next()
				bOK = b.Next()
			}
		case aOK:
			out.Removed = append(out.Removed, a.Record())
			aOK = a.Next()
		case bOK:
			out.Added = append(out.Added, b.Record())
			bOK = b.Next()
		}
	}
	if err := a.Err(); err != nil {
		return nil, err
	}
	if err := b.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
