# macOS Keyboard Acceptance Matrix

**Status:** NEEDS-HARDWARE

This document is a manual acceptance checklist for keyboard input on macOS
Screen Sharing. Each row maps a local key combination to the expected RFB
keysym and remote behavior. Record the observed result on authorized hardware.

## Letters with Shift and Caps Lock

| Local input | Expected keysym | Expected remote result |
| ----------- | --------------- | --------------------- |
| `a` (no modifier) | 0x61 | lowercase 'a' |
| `A` (Shift+a) | 0x41 | uppercase 'A' |
| Caps Lock on, `a` | 0x41 | uppercase 'A' |
| Caps Lock off, `a` | 0x61 | lowercase 'a' |

## Command shortcuts

| Local input | Expected keysym(s) | Expected remote result |
| ----------- | ------------------ | --------------------- |
| Cmd+C | Meta_L(0xFFE7) + c(0x63) | Copy (or clipboard) |
| Cmd+V | Meta_L(0xFFE7) + v(0x76) | Paste (or clipboard) |
| Cmd+Q | Meta_L(0xFFE7) + q(0x71) | Quit application |
| Cmd+Space | Meta_L(0xFFE7) + space(0x20) | Spotlight / input switch |

## Option-generated symbols

| Local input | Expected keysym | Expected remote result |
| ----------- | --------------- | --------------------- |
| Option+e, e | dead-key → é (0xE9) | accented 'é'; use a separate manual clipboard paste if needed |
| Option+1 | ™ (0x2122) | trademark symbol |

## Control sequences

| Local input | Expected keysym | Expected remote result |
| ----------- | --------------- | --------------------- |
| Ctrl+a | Control_L(0xFFE3) + a(0x61) | Ctrl+A (move to line start) |
| Ctrl+c | Control_L(0xFFE3) + c(0x63) | Ctrl+C (interrupt) |

## Navigation keys

| Local input | Expected keysym | Expected remote result |
| ----------- | --------------- | --------------------- |
| ← | 0xFF51 | cursor left |
| → | 0xFF53 | cursor right |
| ↑ | 0xFF52 | cursor up |
| ↓ | 0xFF54 | cursor down |
| Home | 0xFF50 | move to beginning |
| End | 0xFF57 | move to end |
| Page Up | 0xFF55 | scroll up |
| Page Down | 0xFF56 | scroll down |

## Function keys

| Local input | Expected keysym | Expected remote result |
| ----------- | --------------- | --------------------- |
| F1 | 0xFFBE | help / function |
| F2–F12 | 0xFFBF–0xFFC8 | respective function |

## Dead-key / composed-text limitations

Classic RFB KeyEvent input does not support dead keys or IME composition.
For complex composed text (for example, Option+e then e for é), use a separate
manual clipboard paste. The client does not apply that workaround automatically.
