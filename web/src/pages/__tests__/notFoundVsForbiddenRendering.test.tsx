// INV-WEB-06 (#2531), behavioural half: a per-resource-ID page must render a 404 for its
// resource exactly the same as a 403. This is the frontend side of ADR-096's
// 403-for-both convention — the backend collapses "doesn't exist" and "forbidden" for
// any caller without the matching GLOBAL permission; the frontend must not re-open the
// oracle by branching on the status code itself.
//
// Each case renders the REAL page → feature hook → service → apiClient (interceptors
// included); only apiClient's transport adapter is replaced. The resource request fails
// with the same response body under 403 and under 404, so any DOM difference can only
// come from the frontend branching on the status. Every other request succeeds with an
// empty payload, identically in both runs.
//
// Scope: the per-resource-ID routes App.tsx declares (`/projects/:id/*`,
// `/admin/users/:id`). The source-level sweep in
// src/__tests__/structure/noNotFoundBranching.test.ts covers the rest of the tree
// statically. Not compared: authStore.error, which apiClient's interceptor sets on a 403
// only — it is rendered solely on the login page, as a generic "no permission" notice
// that says nothing about the resource's existence.
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios';
import { Routes, Route } from 'react-router';
import { render, screen, cleanup } from '../../test/test-utils';
import { apiClient } from '../../services/client';
import { ProjectDetailPage } from '../projects/ProjectDetailPage';
import { UserDetailPage } from '../admin/UserDetailPage';

vi.mock('../../features/auth', async (orig) => ({
    ...(await orig<typeof import('../../features/auth')>()),
    useAuth: () => ({ user: { id: 1, username: 'admin', role: 'admin', permissions: [] }, isAuthenticated: true }),
}));

const RESOURCE_ID = 42;
const SAME_BODY = { success: false, error: 'Forbidden', message: 'Access denied' };

interface Case {
    name: string;
    routePath: string;
    url: string;
    resourceRequest: string;
    element: React.ReactElement;
    // Text that must appear once the page has settled into its failure state, so the
    // comparison isn't made against two identical loading spinners.
    settledText: RegExp;
}

const cases: Case[] = [
    {
        name: 'ProjectDetailPage',
        routePath: '/projects/:id/*',
        url: `/projects/${RESOURCE_ID}`,
        resourceRequest: `/api/v1/projects/${RESOURCE_ID}`,
        element: <ProjectDetailPage />,
        settledText: /Failed to load project/,
    },
    {
        name: 'UserDetailPage',
        routePath: '/admin/users/:id',
        url: `/admin/users/${RESOURCE_ID}`,
        resourceRequest: `/api/v1/users/${RESOURCE_ID}`,
        element: <UserDetailPage />,
        settledText: /Failed to load user/,
    },
];

let originalAdapter: typeof apiClient.defaults.adapter;

function installAdapter(resourceRequest: string, status: 403 | 404) {
    apiClient.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
        const path = (config.url ?? '').split('?')[0];
        const headers = new AxiosHeaders({ 'content-type': 'application/json' });
        if (path === resourceRequest) {
            const response = {
                status,
                statusText: status === 403 ? 'Forbidden' : 'Not Found',
                data: SAME_BODY,
                headers,
                config,
            };
            throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, {}, response);
        }
        return { status: 200, statusText: 'OK', data: { success: true, data: [] }, headers, config };
    };
}

// React's useId counter is global across roots, so ids differ between two otherwise
// identical renders; normalise them before comparing markup.
const normalise = (html: string) => html.replace(/«[^»]*»|:r[0-9a-z]+:/g, '«id»');

async function renderFailure(c: Case, status: 403 | 404): Promise<string> {
    installAdapter(c.resourceRequest, status);
    window.history.pushState({}, '', c.url);
    const { container, unmount } = render(
        <Routes>
            <Route path={c.routePath} element={c.element} />
        </Routes>
    );
    await screen.findByText(c.settledText);
    const html = normalise(container.innerHTML);
    unmount();
    cleanup();
    return html;
}

describe('INV-WEB-06: per-resource pages render 404 and 403 identically', () => {
    beforeEach(() => {
        originalAdapter = apiClient.defaults.adapter;
    });
    afterEach(() => {
        apiClient.defaults.adapter = originalAdapter;
    });

    it.each(cases)('$name', async (c) => {
        const forbidden = await renderFailure(c, 403);
        const notFound = await renderFailure(c, 404);
        expect(notFound).toBe(forbidden);
    });
});
