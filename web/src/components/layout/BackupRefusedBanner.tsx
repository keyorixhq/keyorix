import React from 'react';
import { useSystemInfo } from '../../features/dashboard/api';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { useAuthStore } from '../../store/authStore';

const STAGING_FILE_REASON = 'key-rotation-staging-file';

/**
 * BackupRefusedBanner warns an administrator while every `admin backup` against this
 * server's key directory is refused (#4105): an interrupted key rotation left a staging
 * file (keys/kek.salt.pending or keys/dek.key.pending), so scheduled backups have
 * stopped. Read from GET /api/v1/system/info (security.backup_refused, present only for
 * system.write callers, one replica's key directory per request). The wording follows
 * docs/operator/j6-key-rotation.md ("When `admin backup` stops after an interrupted
 * rotation"); the remedy sentence is the server's own. It goes away by itself once the
 * file has been moved and the next system info response omits the field.
 */
export const BackupRefusedBanner: React.FC = () => {
    const canFetchInfo = useAuthStore((s) => s.isAuthenticated && !userOwesMfaEnrolment(s.user));
    const { data: sysInfo } = useSystemInfo({ enabled: canFetchInfo });

    const refused = sysInfo?.security?.backup_refused;
    if (!refused) {
        return null;
    }

    const files = refused.files ?? [];
    const exitCode = refused.reason === STAGING_FILE_REASON ? 4 : 1;
    const what =
        refused.reason === STAGING_FILE_REASON
            ? 'Backups are refused: an interrupted key rotation left a staging file in the key directory'
            : 'Backups are refused: the server could not check the key directory for staging files';

    return (
        <div
            role="alert"
            data-testid="backup-refused-banner"
            className="flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white"
            style={{ backgroundColor: 'var(--warning, #b45309)' }}
        >
            <span>
                <strong>{what}</strong>
                {files.length > 0 && <> ({files.join(', ')})</>}. Every <code>admin backup</code> is refused (exit{' '}
                {exitCode}) until it is dealt with, so scheduled backups have stopped. {refused.remedy} Steps:
                &ldquo;When <code>admin backup</code> stops after an interrupted rotation&rdquo; in
                docs/operator/j6-key-rotation.md.
            </span>
        </div>
    );
};
