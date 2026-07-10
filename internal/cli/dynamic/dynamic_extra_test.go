package dynamic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortedKeys(t *testing.T) {
	m := map[string]string{"c": "3", "a": "1", "b": "2"}
	assert.Equal(t, []string{"a", "b", "c"}, sortedKeys(m))
}

func TestSortedKeys_Empty(t *testing.T) {
	assert.Equal(t, []string{}, sortedKeys(map[string]string{}))
}
