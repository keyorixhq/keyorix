### Changed

- Oracle health: `canary-echo-sqlite` no longer carries `KNOWN_BLIND=#4739` and `bounded-json-decode-inner-cap` no longer needs its 6 MB replay generator. Both blind spots were fixed by #4744, so each plant is now detected by the committed seed corpus alone. Test tooling only; no product change.
