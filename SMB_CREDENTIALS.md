# SMB Credentials Management

## Overview

RECON-X now supports secure storage of SMB credentials, eliminating the need to enter credentials every time you run a scan. Credentials are stored securely with file permissions set to `0600` (read/write for owner only).

## Features

- **Secure Storage**: Credentials stored in `~/.recon-x/credentials.json` with restricted file permissions
- **Automatic Detection**: Stored credentials are automatically detected and offered during scans
- **Credential Validation**: Credentials are validated before storage
- **Easy Management**: Simple commands to save, delete, update, and view credentials

## Commands

### View Stored Credentials Summary
```bash
recon-x smb-creds show
```
Displays a summary of stored SMB credentials (password is masked).

### Save/Update Credentials
```bash
recon-x smb-creds save
```
Interactively save new SMB credentials. This will replace any existing stored credentials.

### Delete Credentials
```bash
recon-x smb-creds delete
```
Delete stored SMB credentials from secure storage.

### Interactive Management
```bash
recon-x smb-creds
```
or
```bash
recon-x smb-creds manage
```
Open the interactive credential manager to view, update, or delete credentials.

## Using Stored Credentials During Scans

When you run a scan that requires SMB credentials, RECON-X will:

1. Detect if stored credentials exist
2. Offer to use the stored credentials
3. Allow you to skip credential prompts entirely

### Example Scan with Stored Credentials

```bash
# If credentials are stored, you'll see:
# Found stored SMB credentials.
# Use stored credentials? [Y/n]:

recon-x scan --targets 192.168.1.0/24 --smb-only
```

### Credential Prompt Flow

1. **Ask to use SMB authentication?** - Choose `y` to proceed with SMB scanning
2. **Found stored SMB credentials** - Choose `y` to use them or `n` to enter new ones
3. **Update credentials?** - Choose `y` to replace stored credentials with new ones

## Security Considerations

- Credentials are stored in `~/.recon-x/credentials.json` with restricted permissions (`0600`)
- Only your user account can read or modify stored credentials
- Store credentials only on secure machines
- Consider deleting credentials when working on shared systems
- Never commit credentials files to version control (already in `.gitignore`)

## File Location

Credentials are stored at:
```
~/.recon-x/credentials.json
```

## Credential Storage Format

```json
{
  "smb": {
    "username": "administrator",
    "password": "SecurePassword123",
    "domain": "CORP"
  }
}
```

## Workflow Examples

### Setup Credentials Once
```bash
# First time setup
recon-x smb-creds save
# Enter: admin
# Enter: MyPassword123
# Enter: MYCOMPANY (or leave blank)
# Save for future scans? [Y/n]: y
```

### Run Multiple Scans Without Re-entering Credentials
```bash
# Run scan 1 - uses stored credentials automatically
recon-x scan --targets 192.168.1.100 --smb-only

# Run scan 2 - offers to use stored credentials
recon-x scan --targets 10.0.0.0/24 --smb-only

# Run scan 3 - uses stored credentials
recon-x scan --input targets.txt --smb-only
```

### Update Credentials
```bash
# Interactive update
recon-x smb-creds
# Choose: Update credentials? [y/N]: y
# Enter new credentials

# Or direct save
recon-x smb-creds save
```

### Delete Stored Credentials
```bash
# Delete credentials
recon-x smb-creds delete
# Confirm: Delete stored SMB credentials? [y/N]: y
```

## Troubleshooting

### "No stored credentials found"
- Credentials haven't been saved yet
- Run `recon-x smb-creds save` to save credentials
- Check if file exists: `ls -la ~/.recon-x/credentials.json`

### "Invalid credentials (empty or invalid format)"
- Username or password is empty
- Ensure both fields are filled during credential entry
- Delete and re-save: `recon-x smb-creds delete && recon-x smb-creds save`

### Permission Denied Error
- Check file permissions: `ls -la ~/.recon-x/credentials.json`
- Should show: `-rw-------` (permissions 0600)
- Fix permissions: `chmod 600 ~/.recon-x/credentials.json`

### Credentials Not Being Used
- Verify credentials are stored: `recon-x smb-creds show`
- Check credentials validity: `recon-x smb-creds show`
- Try running scan with SMB option: `recon-x scan --targets <ip> --smb-only`

## Integration with Existing Scans

The credential system works seamlessly with existing scan modes:

```bash
# SMB-only scans
recon-x scan --targets 192.168.1.100 --smb-only

# Full assessment (SMB + other modules)
recon-x scan --targets 10.0.0.0/24 --profile normal

# Manual override (bypasses stored credentials)
recon-x scan --targets 192.168.1.100 --smb-username newuser --smb-password newpass

# From checkpoint/resume
recon-x resume
```

## Best Practices

1. **Save credentials once** - Set them up and reuse across scans
2. **Update regularly** - Change passwords periodically
3. **Secure your system** - Only save credentials on machines you trust
4. **Use strong credentials** - Apply same security policies as actual accounts
5. **Delete before sharing** - Remove credentials if transferring the tool to others
6. **Review permissions** - Ensure file permissions remain `0600`

## Related Commands

- `recon-x scan --help` - See all scan options including SMB parameters
- `recon-x options` - View all scan configurations and modules
- `recon-x version` - Check RECON-X version and capabilities
