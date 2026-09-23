package connect

import "github.com/keyorixhq/keyorix/internal/connect/connecttypes"

// KnownTypes is connecttypes.KnownTypes (the same slice): the list lives in a
// leaf package so internal/config can use it without importing this package
// and, through it, every cloud SDK.
var KnownTypes = connecttypes.KnownTypes
