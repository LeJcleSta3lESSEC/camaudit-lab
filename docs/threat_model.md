# Threat Model

## User threat model

A local Wi-Fi user with no camera credentials attempts to discover whether cameras expose unsafe services.

## Tool threat model

The tool itself could cause harm if it:

- accepts public targets by default
- executes shell commands unsafely
- stores sensitive evidence
- overclaims vulnerabilities
- adds offensive features

## Controls

- private-range target validation
- explicit authorization flag
- subprocess list arguments
- raw evidence isolation
- report redaction
- conservative severity logic
- demo mode for reviewers
