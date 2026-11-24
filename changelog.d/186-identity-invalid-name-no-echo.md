### Security

- A name rejected by validation (`identity.NewFoldedName`, `NewAddressName`) is no longer quoted back in the 400 body or the validation log line. The error reports the position of the first rejected rune instead, so a credential pasted into a name field is not echoed or logged (fuzz-corpus#186).
