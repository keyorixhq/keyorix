# Keyorix Web Dashboard User Guide

Welcome to the Keyorix web dashboard! This guide will help you get started with managing your secrets through the web interface.

## Getting Started

### Logging In

1. Navigate to the Keyorix web dashboard
2. Enter your email and password
3. Click "Sign In"
4. If you have two-factor authentication enabled, enter your verification code

### Dashboard Overview

After logging in, you'll see the main dashboard with:
- **Statistics**: Overview of your secrets, shares, and recent activity
- **Recent Activity**: Timeline of recent actions
- **Quick Actions**: Shortcuts to common tasks
- **System Status**: Health indicators for the system

## Managing Secrets

### Creating a Secret

1. Navigate to **Secrets** in the sidebar
2. Click **Create Secret**
3. Fill in the required information:
   - **Name**: Unique identifier for your secret
   - **Type**: Choose from text, password, JSON, or file
   - **Value**: The secret content
   - **Namespace**: Organizational grouping (optional)
   - **Zone**: Deployment zone (optional)
   - **Environment**: Environment designation (optional)
   - **Tags**: Labels for categorization (optional)
4. Click **Create Secret**

### Viewing Secrets

1. Go to the **Secrets** page
2. Browse the list of secrets
3. Use the search bar to find specific secrets
4. Filter by namespace, type, or tags
5. Click on a secret name to view details

### Editing Secrets

1. Find the secret you want to edit
2. Click the **Edit** button (pencil icon)
3. Modify the fields as needed
4. Click **Update Secret**

### Deleting Secrets

1. Find the secret you want to delete
2. Click the **Delete** button (trash icon)
3. Confirm the deletion in the popup dialog

**Warning**: Deleted secrets cannot be recovered!

## Secret Sharing

### Sharing a Secret

1. Navigate to the secret you want to share
2. Click **Share** in the secret details view
3. Select recipients:
   - Enter email addresses for individual users
   - Select groups from the dropdown
4. Set permissions:
   - **Read**: View the secret value
   - **Write**: Modify the secret
5. Set expiration (optional):
   - Choose a date when access should expire
6. Click **Share Secret**

### Managing Shares

1. Go to **Sharing** in the sidebar
2. View all your shared secrets
3. For each share, you can:
   - **Edit permissions**: Change read/write access
   - **Update expiration**: Modify or remove expiration date
   - **Revoke access**: Remove sharing permissions
   - **View history**: See sharing activity

### Accessing Shared Secrets

1. Shared secrets appear in your **Secrets** list
2. They're marked with a "shared" indicator
3. Your permissions determine what actions you can perform
4. You can remove yourself from shares using the **Leave Share** option

## User Profile and Settings

### Profile Management

1. Click your avatar in the top-right corner
2. Select **Profile** from the dropdown
3. Update your information:
   - Name and email
   - Profile picture
   - Contact preferences

### Security Settings

1. Go to **Profile** → **Security**
2. Available options:
   - **Change Password**: Update your login password
   - **Two-Factor Authentication**: Enable/disable 2FA
   - **Active Sessions**: View and manage login sessions
   - **API Keys**: Generate keys for programmatic access

### Preferences

1. Navigate to **Profile** → **Preferences**
2. Customize your experience:
   - **Language**: Choose your preferred language
   - **Theme**: Select light, dark, or system theme
   - **Timezone**: Set your local timezone
   - **Notifications**: Configure email and in-app notifications

## Search and Filtering

### Search Functionality

- **Global Search**: Use the search bar in the header
- **Secret Search**: Filter secrets by name, content, or metadata
- **Advanced Search**: Use operators like `type:password` or `tag:production`

### Filtering Options

- **By Type**: Filter secrets by their type (password, text, JSON, etc.)
- **By Namespace**: Show secrets from specific namespaces
- **By Environment**: Filter by environment (dev, staging, prod)
- **By Tags**: Select one or more tags to filter
- **By Date**: Show secrets created or modified within a date range

## Analytics and Reporting

### Usage Analytics

1. Go to **Analytics** in the sidebar
2. View insights about:
   - Secret creation trends
   - Sharing activity
   - User engagement
   - Security events

### Activity Timeline

1. Navigate to **Activity** to see:
   - Recent actions across the system
   - Detailed audit logs
   - User activity patterns
   - Security-related events

### Exporting Data

1. Most views include an **Export** button
2. Choose your preferred format (CSV, JSON, PDF)
3. Select date ranges and filters
4. Download the generated report

## Administration (Admin Users Only)

### User Management

1. Go to **Admin** → **Users**
2. Manage user accounts:
   - Create new users
   - Edit user permissions
   - Disable or delete accounts
   - Reset passwords

### Role Management

1. Navigate to **Admin** → **Roles**
2. Configure roles and permissions:
   - Create custom roles
   - Assign permissions to roles
   - Manage role hierarchies

### System Settings

1. Access **Admin** → **Settings**
2. Configure system-wide options:
   - Security policies
   - Backup settings
   - Integration configurations
   - Feature toggles

## Mobile Usage

The web dashboard is fully responsive and works on mobile devices:

- **Touch-friendly interface**: Optimized for touch interactions
- **Responsive design**: Adapts to different screen sizes
- **Offline support**: Basic functionality available offline
- **Mobile notifications**: Push notifications for important events

## Keyboard Shortcuts

Speed up your workflow with keyboard shortcuts:

- `Ctrl/Cmd + K`: Open global search
- `Ctrl/Cmd + N`: Create new secret
- `Ctrl/Cmd + S`: Save current form
- `Escape`: Close modals and dropdowns
- `Tab`: Navigate between form fields
- `Enter`: Submit forms or confirm actions

## Accessibility Features

The dashboard includes comprehensive accessibility support:

- **Screen reader compatibility**: Full ARIA support
- **Keyboard navigation**: Navigate without a mouse
- **High contrast mode**: Better visibility for low vision users
- **Reduced motion**: Respects motion sensitivity preferences
- **Focus indicators**: Clear visual focus indicators

## Troubleshooting

### Common Issues

**Can't log in**:
- Check your email and password
- Ensure caps lock is off
- Try resetting your password
- Contact your administrator

**Secrets not loading**:
- Check your internet connection
- Refresh the page
- Clear browser cache
- Try a different browser

**Sharing not working**:
- Verify recipient email addresses
- Check your sharing permissions
- Ensure the secret exists
- Contact support if issues persist

### Getting Help

- **In-app help**: Click the help icon (?) for contextual assistance
- **Documentation**: Access full documentation from the help menu
- **Support**: Contact your system administrator or support team
- **Feedback**: Use the feedback form to report issues or suggestions

## Security Best Practices

### Password Security

- Use strong, unique passwords
- Enable two-factor authentication
- Regularly update your password
- Don't share your login credentials

### Secret Management

- Use descriptive names for secrets
- Regularly review and clean up unused secrets
- Be cautious when sharing sensitive information
- Set appropriate expiration dates for shares

### Account Security

- Log out when using shared computers
- Monitor your active sessions
- Review sharing permissions regularly
- Report suspicious activity immediately

## Tips and Best Practices

### Organization

- Use consistent naming conventions
- Leverage namespaces for organization
- Tag secrets appropriately
- Document important secrets with metadata

### Collaboration

- Share secrets with specific permissions
- Use groups for team-based sharing
- Set expiration dates for temporary access
- Communicate changes to team members

### Efficiency

- Use keyboard shortcuts
- Bookmark frequently accessed secrets
- Set up custom filters for common searches
- Take advantage of bulk operations

This guide covers the essential features of the Keyorix web dashboard. For more detailed information or advanced features, consult the full documentation or contact your system administrator.