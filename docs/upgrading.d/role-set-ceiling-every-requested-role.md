## Setting a member's roles needs authority over every requested role

`PUT /api/v1/projects/{id}/members/{userId}` and `PUT /api/v1/users/{id}/roles` now check the
granter ceiling on every requested role, not only on roles the request adds.

Before: a `roles.assign` holder who could not grant role X got 200 when the target already held X,
either because nothing changed or because the request only removed the target's other roles.

Now: the same request answers 403 and changes nothing. The caller must hold every permission each
requested role bundles. Roles the request removes are not judged, so removing a role the caller
could not grant still works when every role that stays is within the caller's authority.

What to do: an integration that sends a member's full role set through either route with a
credential that cannot grant one of those roles must use a credential that can, or stop sending
the request. `POST /api/v1/projects/{id}/memberships` also now answers 403 instead of 500 for a
role the caller may not grant.
