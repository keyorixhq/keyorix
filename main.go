/*
Keyorix - Enterprise Secret Management System
Copyright (C) 2025 Keyorix Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"syscall"

	"github.com/keyorixhq/keyorix/internal/cli"
)

func main() {
	// #1647: the CLI shares internal/storage/factory.go's local-SQLite path with the
	// server, and without an explicit mode the driver creates the database (and its
	// -wal/-shm sidecars) at SQLITE_DEFAULT_FILE_PERMISSIONS (0644) masked only by
	// whatever umask this process inherited from its parent shell/supervisor -- a
	// systemd unit with no UMask= commonly leaves that at 022, shipping the live
	// secrets database world-readable with no error or log line. Setting an explicit,
	// restrictive process umask here means every file this binary EVER creates -- not
	// just the ones a call site remembers to pass 0600 to -- is born correct.
	syscall.Umask(0o077)
	cli.Execute()
}
